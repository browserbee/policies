package main

import rego.v1

test_allow_valid_openapi_spec if {
  spec := {
    "openapi": "3.0.3",
    "info": {
      "title": "Example API",
      "version": "1.0.0"
    },
    "paths": {
      "/documents": {
        "get": {
          "operationId": "listDocuments",
          "responses": {
            "200": {"description": "OK"},
            "400": {"description": "Bad request"}
          }
        }
      }
    }
  }

  count(deny) with input as spec == 0
}

test_deny_missing_operation_id if {
  spec := {
    "openapi": "3.0.3",
    "info": {
      "title": "Example API",
      "version": "1.0.0"
    },
    "paths": {
      "/documents": {
        "get": {
          "responses": {
            "200": {"description": "OK"},
            "400": {"description": "Bad request"}
          }
        }
      }
    }
  }

  count(deny) with input as spec > 0
}

test_deny_missing_error_response if {
  spec := {
    "openapi": "3.0.3",
    "info": {
      "title": "Example API",
      "version": "1.0.0"
    },
    "paths": {
      "/documents": {
        "get": {
          "operationId": "listDocuments",
          "responses": {
            "200": {"description": "OK"}
          }
        }
      }
    }
  }

  count(deny) with input as spec > 0
}

test_deny_missing_info_fields if {
  spec := {
    "openapi": "3.0.3",
    "info": {},
    "paths": {}
  }

  count(deny) with input as spec > 0
}
