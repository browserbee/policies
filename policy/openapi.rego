package main

import rego.v1

http_methods := {"get", "put", "post", "delete", "patch", "head", "options", "trace"}
input_obj := input if is_object(input) else := {}

is_openapi_input if {
  object.get(input_obj, "paths", null) != null
  object.get(input_obj, "info", null) != null
}

api_operations contains op if {
  paths := object.get(input_obj, "paths", {})
  some path, path_item in paths
  some method, operation in path_item
  normalized_method := lower(method)
  http_methods[normalized_method]
  is_object(operation)
  op := {
    "path": path,
    "method": normalized_method,
    "operation": operation,
  }
}

has_error_response(operation) if {
  responses := object.get(operation, "responses", {})
  some code, _ in responses
  response_code := lower(sprintf("%v", [code]))
  not startswith(response_code, "2")
}

deny contains msg if {
  is_openapi_input
  info := object.get(input_obj, "info", {})
  trim_space(object.get(info, "title", "")) == ""
  msg := "OpenAPI info.title is required."
}

deny contains msg if {
  is_openapi_input
  info := object.get(input_obj, "info", {})
  trim_space(object.get(info, "version", "")) == ""
  msg := "OpenAPI info.version is required."
}

deny contains msg if {
  is_openapi_input
  op := api_operations[_]
  trim_space(object.get(op.operation, "operationId", "")) == ""
  msg := sprintf("OpenAPI operation %s %s is missing operationId.", [upper(op.method), op.path])
}

deny contains msg if {
  is_openapi_input
  op := api_operations[_]
  not has_error_response(op.operation)
  msg := sprintf("OpenAPI operation %s %s must define at least one non-2xx error response.", [upper(op.method), op.path])
}
