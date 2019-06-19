/*
 * Copyright (c) 2014-2019 Snowplow Analytics Ltd. All rights reserved.
 *
 * This program is licensed to you under the Apache License Version 2.0,
 * and you may not use this file except in compliance with the Apache License Version 2.0.
 * You may obtain a copy of the Apache License Version 2.0 at http://www.apache.org/licenses/LICENSE-2.0.
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the Apache License Version 2.0 is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Apache License Version 2.0 for the specific language governing permissions and limitations there under.
 */
package com.snowplowanalytics.snowplow.enrich.common
package adapters
package registry

import scala.util.Try

import cats.Monad
import cats.data.{NonEmptyList, ValidatedNel}
import cats.effect.Clock
import cats.syntax.apply._
import cats.syntax.either._
import cats.syntax.option._
import cats.syntax.validated._
import com.snowplowanalytics.iglu.client.Client
import com.snowplowanalytics.iglu.client.resolver.registries.RegistryLookup
import com.snowplowanalytics.snowplow.badrows.AdapterFailure
import com.snowplowanalytics.snowplow.badrows.AdapterFailure.InputDataAdapterFailure
import io.circe._
import org.joda.time.DateTime

import loaders.{CollectorContext, CollectorPayload}
import utils.{ConversionUtils, HttpClient}

/** Transforms a Cloudfront access log into raw events */
object CloudfrontAccessLogAdapter extends Adapter {

  private val FieldNames = List(
    "dateTime",
    "xEdgeLocation",
    "scBytes",
    "cIp",
    "csMethod",
    "csHost",
    "csUriStem",
    "scStatus",
    "csReferer",
    "csUserAgent",
    "csUriQuery",
    "csCookie",
    "xEdgeResultType",
    "xEdgeRequestId",
    "xHostHeader",
    "csProtocol",
    "csBytes",
    "timeTaken",
    "xForwardedFor",
    "sslProtocol",
    "sslCipher",
    "xEdgeResponseResultType",
    "csProtocolVersion",
    "fleStatus",
    "fleEncryptedFields"
  )

  // Tracker version for Cloudfront access log
  private val TrackerVersion = "com.amazon.aws.cloudfront/wd_access_log"

  /**
   * Converts a CollectorPayload instance into raw events.
   * Chooses a wd_access_log schema version based on the length of the TSV.
   * Extracts the collector timestamp and IP address from the TSV.
   * @param payload Generated by the TsvLoader. Its body is the raw TSV.
   * @param client The Iglu client used for schema lookup and validation
   * @return a validation boxing either a NEL of raw events or a NEL of failure strings
   */
  override def toRawEvents[F[_]: Monad: RegistryLookup: Clock: HttpClient](
    payload: CollectorPayload,
    client: Client[F, Json]
  ): F[ValidatedNel[AdapterFailure, NonEmptyList[RawEvent]]] =
    payload.body match {
      case Some(p) =>
        val _ = client
        val fields = p.split("\t", -1)
        val schemaVersion = fields.size match {
          case 12 => "1-0-0".asRight // Before 12 Sep 2012
          case 15 => "1-0-1".asRight // 12 Sep 2012
          case 18 => "1-0-2".asRight // 21 Oct 2013
          case 19 => "1-0-3".asRight // 29 Apr 2014
          case 23 => "1-0-4".asRight // 01 Jul 2015
          case 24 => "1-0-5".asRight // 29 Sep 2016
          case 26 => "1-0-6".asRight
          case n =>
            val msg = s"access log contained $n fields, expected 12, 15, 18, 19, 23, 24 or 26"
            val failure = InputDataAdapterFailure("body", p.some, msg)
            NonEmptyList.one(failure).asLeft
        }
        val result = schemaVersion
          .flatMap(v => buildRawEvents(v, fields.toList, payload))
          .toValidated
        Monad[F].pure(result)
      case None =>
        val failure = InputDataAdapterFailure("body", None, "empty body")
        Monad[F].pure(failure.invalidNel)
    }

  /**
   * Converts a CloudFront log-format date and a time to a timestamp.
   * @param date The CloudFront log-format date
   * @param time The CloudFront log-format time
   * @return the timestamp as a Joda DateTime or an error String, all wrapped in a Validation
   */
  def toTimestamp(date: String, time: String): Either[AdapterFailure, DateTime] =
    Either
      .catchNonFatal(DateTime.parse("%sT%s+00:00".format(date, time)))
      .leftMap { e =>
        val msg = s"could not convert access log timestamp: ${e.getMessage}"
        InputDataAdapterFailure("dateTime", s"$date $time".some, msg)
      }

  private def buildRawEvents(
    schemaVersion: String,
    fields: List[String],
    payload: CollectorPayload
  ): Either[NonEmptyList[AdapterFailure], NonEmptyList[RawEvent]] = {
    // Combine the first two fields into a timestamp
    val schemaCompatibleFields =
      "%sT%sZ".format(fields(0), fields(1)) :: fields.tail.tail
    val ip = schemaCompatibleFields(3) match {
      case "" => None
      case nonempty => nonempty.some
    }
    val qsParams: Map[String, String] = schemaCompatibleFields(8) match {
      case "" => Map()
      case url => Map("url" -> url)
    }
    val userAgent = schemaCompatibleFields(9) match {
      case "" => None
      case nonempty => ConversionUtils.singleEncodePcts(nonempty).some
    }

    val (errors, ueJson) =
      buildJson(Nil, FieldNames zip schemaCompatibleFields, JsonObject.empty)

    val failures = errors match {
      case Nil => "".valid
      case h :: t => NonEmptyList.of(h, t: _*).invalid // list to nonemptylist
    }

    val validatedTstamp = toTimestamp(fields(0), fields(1)).map(Some(_)).toValidatedNel

    (validatedTstamp, failures).mapN { (tstamp, _) =>
      val parameters = toUnstructEventParams(
        TrackerVersion,
        qsParams,
        s"iglu:com.amazon.aws.cloudfront/wd_access_log/jsonschema/$schemaVersion",
        ueJson,
        "srv"
      )
      NonEmptyList.one(
        RawEvent(
          api = payload.api,
          parameters = parameters,
          contentType = payload.contentType,
          source = payload.source,
          context = CollectorContext(tstamp, ip, userAgent, None, Nil, None)
        )
      )
    }.toEither
  }

  // Attempt to build the json, accumulating errors from unparseable fields
  private def buildJson(
    errors: List[AdapterFailure],
    fields: List[(String, String)],
    json: JsonObject
  ): (List[AdapterFailure], JsonObject) =
    fields match {
      case Nil => (errors, json)
      case head :: tail =>
        head match {
          case (name, "") => buildJson(errors, tail, json.add(name, Json.Null))
          case ("timeTaken", field) =>
            val jsonField = for {
              d <- Try(field.toDouble).toOption
              js <- Json.fromDouble(d)
            } yield js
            jsonField match {
              case Some(f) => buildJson(errors, tail, json.add("timeTaken", f))
              case None =>
                val msg = "cannot be converted to Double"
                val failure = InputDataAdapterFailure("timeTaken", field.some, msg)
                buildJson(failure :: errors, tail, json)
            }
          case (name, field) if name == "csBytes" || name == "scBytes" =>
            Try(field.toInt).toOption match {
              case Some(i) => buildJson(errors, tail, json.add(name, Json.fromInt(i)))
              case None =>
                val msg = "cannot be converted to Int"
                val failure = InputDataAdapterFailure(name, field.some, msg)
                buildJson(failure :: errors, tail, json)
            }
          case (name, field) if name == "csReferer" || name == "csUserAgent" =>
            ConversionUtils
              .doubleDecode(field)
              .fold(
                e => buildJson(InputDataAdapterFailure(name, field.some, e) :: errors, tail, json),
                s => buildJson(errors, tail, json.add(name, Json.fromString(s)))
              )
          case ("csUriQuery", field) =>
            buildJson(
              errors,
              tail,
              json.add("csUriQuery", Json.fromString(ConversionUtils.singleEncodePcts(field)))
            )
          case (name, field) => buildJson(errors, tail, json.add(name, Json.fromString(field)))
        }
    }
}
