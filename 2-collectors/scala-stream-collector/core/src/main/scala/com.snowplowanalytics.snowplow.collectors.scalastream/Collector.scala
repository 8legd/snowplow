/*
 * Copyright (c) 2013-2019 Snowplow Analytics Ltd. All rights reserved.
 *
 * This program is licensed to you under the Apache License Version 2.0, and
 * you may not use this file except in compliance with the Apache License
 * Version 2.0.  You may obtain a copy of the Apache License Version 2.0 at
 * http://www.apache.org/licenses/LICENSE-2.0.
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Apache License Version 2.0 is distributed on an "AS
 * IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.  See the Apache License Version 2.0 for the specific language
 * governing permissions and limitations there under.
 */
package com.snowplowanalytics.snowplow
package collectors
package scalastream

import java.io.File
import javax.net.ssl.SSLContext

import akka.actor.ActorSystem
import akka.http.scaladsl.{ConnectionContext, Http}
import akka.http.scaladsl.server.Directives._
import akka.stream.{ActorMaterializer, TLSClientAuth}
import com.snowplowanalytics.snowplow.collectors.scalastream.metrics._
import com.snowplowanalytics.snowplow.collectors.scalastream.model._
import com.typesafe.config.{Config, ConfigFactory}
import com.typesafe.sslconfig.akka.AkkaSSLConfig
import com.typesafe.sslconfig.akka.util.AkkaLoggerFactory
import com.typesafe.sslconfig.ssl.ConfigSSLContextBuilder
import com.typesafe.sslconfig.ssl.{ClientAuth => SslClientAuth}
import org.slf4j.LoggerFactory
import pureconfig._

// Main entry point of the Scala collector.
trait Collector {

  lazy val log = LoggerFactory.getLogger(getClass())

  def parseConfig(args: Array[String]): (CollectorConfig, Config) = {
    case class FileConfig(config: File = new File("."))
    val parser = new scopt.OptionParser[FileConfig](generated.BuildInfo.name) {
      head(generated.BuildInfo.name, generated.BuildInfo.version)
      help("help")
      version("version")
      opt[File]("config").required().valueName("<filename>")
        .action((f: File, c: FileConfig) => c.copy(f))
        .validate(f =>
          if (f.exists) success
          else failure(s"Configuration file $f does not exist")
        )
    }

    val conf = parser.parse(args, FileConfig()) match {
      case Some(c) => ConfigFactory.parseFile(c.config).resolve()
      case None    => ConfigFactory.empty()
    }

    if (!conf.hasPath("collector")) {
      System.err.println("configuration has no \"collector\" path")
      System.exit(1)
    }

    implicit def hint[T] = ProductHint[T](ConfigFieldMapping(CamelCase, CamelCase))
    implicit val sinkConfigHint = new FieldCoproductHint[SinkConfig]("enabled")
    (loadConfigOrThrow[CollectorConfig](conf.getConfig("collector")), conf)
  }

  private def secureConnectionContext(system: ActorSystem, sslConfig: AkkaSSLConfig) = {
    val config = sslConfig.config

    val sslContext = if (sslConfig.config.default) {
      sslConfig.validateDefaultTrustManager(config)
      SSLContext.getDefault
    } else {
      val mkLogger = new AkkaLoggerFactory(system)
      val keyManagerFactory   = sslConfig.buildKeyManagerFactory(config)
      val trustManagerFactory = sslConfig.buildTrustManagerFactory(config)
      new ConfigSSLContextBuilder(mkLogger, config, keyManagerFactory, trustManagerFactory).build()
    }

    val defaultParams    = sslContext.getDefaultSSLParameters
    val defaultProtocols = defaultParams.getProtocols
    val protocols        = sslConfig.configureProtocols(defaultProtocols, config)
    defaultParams.setProtocols(protocols)

    val defaultCiphers = defaultParams.getCipherSuites
    val cipherSuites   = sslConfig.configureCipherSuites(defaultCiphers, config)
    defaultParams.setCipherSuites(cipherSuites)

    val clientAuth: Option[TLSClientAuth] = config.sslParametersConfig.clientAuth match {
      case SslClientAuth.Default => None
      case SslClientAuth.Want =>
        defaultParams.setWantClientAuth(true)
        Some(TLSClientAuth.Want)
      case SslClientAuth.Need =>
        defaultParams.setNeedClientAuth(true)
        Some(TLSClientAuth.Need)
      case SslClientAuth.None =>
        defaultParams.setNeedClientAuth(false)
        Some(TLSClientAuth.None)
    }

    if (!sslConfig.config.loose.disableHostnameVerification) {
      defaultParams.setEndpointIdentificationAlgorithm("HTTPS")
    }

    ConnectionContext.https(
      sslContext,
      Some(sslConfig),
      Some(cipherSuites.toList),
      Some(defaultProtocols.toList),
      clientAuth,
      Some(defaultParams)
    )
  }

  def run(collectorConf: CollectorConfig, akkaConf: Config, sinks: CollectorSinks): Unit = {

    implicit val system = ActorSystem.create("scala-stream-collector", akkaConf)
    implicit val materializer = ActorMaterializer()
    implicit val executionContext = system.dispatcher

    val collectorRoute = new CollectorRoute {
      override def collectorService = new CollectorService(collectorConf, sinks)
    }

    val prometheusMetricsService = new PrometheusMetricsService(collectorConf.prometheusMetrics)

    val metricsRoute = new MetricsRoute {
      override def metricsService: MetricsService = prometheusMetricsService
    }

    val metricsDirectives = new MetricsDirectives {
      override def metricsService: MetricsService = prometheusMetricsService
    }

    val connectionContext = if (!collectorConf.ssl) ConnectionContext.noEncryption() else secureConnectionContext(system, AkkaSSLConfig())

    val routes =
      if (collectorConf.prometheusMetrics.enabled)
        metricsRoute.metricsRoute ~ metricsDirectives.logRequest(collectorRoute.collectorRoute)
      else collectorRoute.collectorRoute

    Http().bindAndHandle(routes, collectorConf.interface, collectorConf.port, connectionContext)
      .map { binding =>
        log.info(s"REST interface bound to ${binding.localAddress}")
      } recover { case ex =>
        log.error("REST interface could not be bound to " +
          s"${collectorConf.interface}:${collectorConf.port}", ex.getMessage)
      }
  }
}
