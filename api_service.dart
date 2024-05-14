import 'dart:convert';
import 'dart:developer';
import 'dart:io';

import 'package:admin/constants/api_path.dart';
import 'package:admin/constants/secure_storage_path.dart';
import 'package:admin/utils/helpers/common_helpers.dart';
import 'package:admin/utils/services/api/api_exceptions.dart';
import 'package:dio/dio.dart';
import 'package:flutter/services.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:jwt_decode_full/jwt_decode_full.dart';
import 'package:http/http.dart' as http;

class RestAPIService {
  final Dio _dio;

  RestAPIService(this._dio);

  getHeaders(bool useToken) async {
    const FlutterSecureStorage storage = FlutterSecureStorage();
    String? token = await storage.read(key: SecureStoragePath.accessToken);

    _dio.options.headers['Content-Type'] = 'application/json';
    if (useToken) _dio.options.headers["Authorization"] = "Bearer $token";
    // showLog("TOKEN ====>>>> $token");
  }

  Future<dynamic> postService(
      {required String url,
      body,
      useToken = true,
      bool isMultiPart = false}) async {
    String fetchUrl;
    try {
      if (useToken) {
        String loginStatus = await checkExpiry();
        if (loginStatus.compareTo('token_expired') == 0) {
          await refreshToken();
        }
      }
      // debugger();

      await getHeaders(useToken);
      if (url.contains("http")) {
        fetchUrl = url;
      } else {
        fetchUrl = AdminAppAPI.baseUrl + url;
      }

      Options options = Options();
      if (isMultiPart) {
        options = Options(contentType: 'multipart/form-data');
      }

      showLog(_dio.options.headers.toString());
      showLog("URL ====>>>>>> POST : $fetchUrl");
      showLog("BODY ====>>>>>>$body");
      // debugger();
      var response = await _dio.post(fetchUrl, data: body, options: options);

      showLog("RESPONSE ====>>>>>>${response.data}");
      //debugger();
      return response.data;
    } on DioError catch (dioError) {
      // debugger();
      showLog("error is : ${dioError.response}");
      if (RestAPIException.fromDioError(dioError).message == "Unauthorized") {
        showUnAuthorisedPopUp();
      }
      throw RestAPIException.fromDioError(dioError);
    }
  }

  Future<dynamic> postFileService(
      {required String url,
      body,
      imageFile,
      useToken = true,
      bool isMultiPart = false}) async {
    String fetchUrl;
    try {
      if (useToken) {
        String loginStatus = await checkExpiry();
        if (loginStatus.compareTo('token_expired') == 0) {
          await refreshToken();
        }
      }
      // debugger();

      await getHeaders(useToken);
      if (url.contains("http")) {
        fetchUrl = url;
      } else {
        fetchUrl = AdminAppAPI.baseUrl + url;
      }

      showLog(_dio.options.headers.toString());
      showLog("URL ====>>>>>> POST : $fetchUrl");
      showLog("BODY ====>>>>>>$body");
      // showLog("File ====>>>>>>$imageFile");
      // debugger();

      var response = await _dio.post(
        fetchUrl,
        data: body,
      );

      showLog("RESPONSE ====>>>>>>${response.data}");
      //debugger();
      return response.data;
    } on DioError catch (dioError) {
      // debugger();
      showLog("error is : ${dioError.response}");
      if (RestAPIException.fromDioError(dioError).message == "Unauthorized") {
        showUnAuthorisedPopUp();
      }
      throw RestAPIException.fromDioError(dioError);
    }
  }

  getService({required String url, useToken = true}) async {
    String fetchUrl;
    try {
      if (useToken) {
        String loginStatus = await checkExpiry();
        if (loginStatus.compareTo('token_expired') == 0) {
          await refreshToken();
        }
      }
      await getHeaders(useToken);

      if (url.contains("http")) {
        fetchUrl = url;
      } else {
        fetchUrl = AdminAppAPI.baseUrl + url;
      }

      showLog("HEADERS ====>>>>>>${_dio.options.headers}");
      showLog("URL ====>>>>>> GET : $fetchUrl");
      var response = await _dio.get(fetchUrl);
      // debugger();
      // print(response);
      showLog("RESPONSE ====>>>>>>${response.data.toString()}");
      return response.data;
    } on DioError catch (dioError) {
      showLog(dioError.message);
      // if (RestAPIException.fromDioError(dioError).message == "Unauthorized") {
      //   showUnAuthorisedPopUp();
      // }
      throw RestAPIException.fromDioError(dioError);
    }
  }

  getImageService({required String url, useToken = true}) async {
    String fetchUrl;
    try {
      if (useToken) {
        String loginStatus = await checkExpiry();
        if (loginStatus.compareTo('token_expired') == 0) {
          await refreshToken();
        }
      }
      await getHeaders(useToken);

      if (url.contains("http")) {
        fetchUrl = url;
      } else {
        fetchUrl = AdminAppAPI.baseUrl + url;
      }

      showLog("HEADERS ====>>>>>>${_dio.options.headers}");
      showLog("URL ====>>>>>> GET : $fetchUrl");
      var response = await _dio.get(fetchUrl,
          options: Options(responseType: ResponseType.bytes));
      // debugger();
      // print(response);
      // showLog("RESPONSE ====>>>>>>${response.data.toString()}");
      return response.data;
    } on DioError catch (dioError) {
      showLog(dioError.message);
      // if (RestAPIException.fromDioError(dioError).message == "Unauthorized") {
      //   showUnAuthorisedPopUp();
      // }
      throw RestAPIException.fromDioError(dioError);
    }
  }

  deleteService({required String url, useToken = true}) async {
    String fetchUrl;
    try {
      if (useToken) {
        String loginStatus = await checkExpiry();
        if (loginStatus.compareTo('token_expired') == 0) {
          await refreshToken();
        }
      }
      await getHeaders(useToken);

      if (url.contains("http")) {
        fetchUrl = url;
      } else {
        fetchUrl = AdminAppAPI.baseUrl + url;
      }

      //showLog("HEADERS ====>>>>>>" + _dio.options.headers.toString());
      showLog("URL ====>>>>>> DELETE : $fetchUrl");

      var response = await _dio.delete(
        fetchUrl,
      );
      //showLog("BODY ====>>>>>>" + body.toString());

      showLog("RESPONSE ====>>>>>>${response.data}");
      return response.data;
    } on DioError catch (dioError) {
      showLog(dioError.message);
      // if (RestAPIException.fromDioError(dioError).message == "Unauthorized") {
      //   showUnAuthorisedPopUp();
      // }
      throw RestAPIException.fromDioError(dioError);
    }
  }

  putService({required String url, useToken = true, body}) async {
    String fetchUrl;
    try {
      if (useToken) {
        String loginStatus = await checkExpiry();
        if (loginStatus.compareTo('token_expired') == 0) {
          await refreshToken();
        }
      }
      await getHeaders(useToken);

      if (url.contains("http")) {
        fetchUrl = url;
      } else {
        fetchUrl = AdminAppAPI.baseUrl + url;
      }

      //showLog("HEADERS ====>>>>>>" + _dio.options.headers.toString());
      showLog("URL ====>>>>>> PUT : $fetchUrl");

      var response = await _dio.put(fetchUrl, data: body);
      showLog("BODY ====>>>>>>$body");

      showLog("RESPONSE ====>>>>>>${response.data}");
      return response.data;
    } on DioError catch (dioError) {
      showLog(dioError.message);
      // if (RestAPIException.fromDioError(dioError).message == "Unauthorized") {
      //   showUnAuthorisedPopUp();
      // }
      throw RestAPIException.fromDioError(dioError);
    }
  }

  Future<dynamic> patchService(
      {required String url, body, useToken = true}) async {
    String fetchUrl;
    try {
      await getHeaders(useToken);
      if (url.contains("http")) {
        fetchUrl = url;
      } else {
        fetchUrl = AdminAppAPI.baseUrl + url;
      }

      var response = await _dio.patch(fetchUrl, data: body);
      showLog("URL ====>>>>>> PATCH : $fetchUrl");
      showLog("BODY ====>>>>>>$body");
      showLog("RESPONSE ====>>>>>>${response.data}");
      return response.data;
    } on DioError catch (dioError) {
      showLog(dioError.message);
      throw RestAPIException.fromDioError(dioError);
    }
  }

  Future refreshToken() async {
    try {
      const FlutterSecureStorage storage = FlutterSecureStorage();

      String username =
          await storage.read(key: SecureStoragePath.username) ?? '';
      String password =
          await storage.read(key: SecureStoragePath.password) ?? '';
      Map signInMap = {
        "prefix": AdminAppAPI.prefix,
        "username": username,
        "password": password,
      };
      var response = await _dio.post(
        AdminAppAPI.baseUrl + AdminAppAPI.signInUrl,
        data: signInMap,
      );

      await storage.write(
          key: SecureStoragePath.accessToken, value: response.data['token']);
    } on DioError catch (dioError) {
      showLog("error is : ${dioError.response}");
      throw RestAPIException.fromDioError(dioError);
    }
  }

  Future<String> checkExpiry() async {
    const FlutterSecureStorage storage = FlutterSecureStorage();
    String result;

    String token = await storage.read(key: SecureStoragePath.accessToken) ?? '';
    final jwtData = jwtDecode(token);

    showLog('header: ${jwtData.header}');
    showLog('payload: ${jwtData.payload}');
    showLog('isExpired: ${jwtData.isExpired}');
    showLog('issued date: ${jwtData.issuedAt}');
    showLog('expiration date: ${jwtData.expiration}');
    if (jwtData.isExpired ?? true) {
      result = 'token_expired';
      return result;
    } else {
      result = 'active';
      return result;
    }
  }

  /**
   * Bellow code is new code
   */
  getServiceAfterLogin({required String url, useToken = true}) async {
    String fetchUrl;
    try {
      if (useToken) {
        String loginStatus = await checkExpiry();
        if (loginStatus.compareTo('token_expired') == 0) {
          await refreshToken();
        }
      }

      if (url.contains("http")) {
        fetchUrl = url;
      } else {
        fetchUrl = AdminAppAPI.baseUrl + url;
      }

      showLog("HEADERS ====>>>>>>${_dio.options.headers}");
      showLog("URL ====>>>>>> GET : $fetchUrl");
      const FlutterSecureStorage storage = FlutterSecureStorage();
      String? token = await storage.read(key: SecureStoragePath.accessToken);
      print(token);
      var res = await http.get(Uri.parse(fetchUrl), headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer $token'
      });
// debugger();
      if (res.statusCode == 200) {
        return json.decode(res.body);
      }
    } on DioError catch (dioError) {
      debugger();
      print(dioError);
      showLog(dioError.message);
      // if (RestAPIException.fromDioError(dioError).message == "Unauthorized") {
      //   showUnAuthorisedPopUp();
      // }
      throw RestAPIException.fromDioError(dioError);
    }
  }
}
