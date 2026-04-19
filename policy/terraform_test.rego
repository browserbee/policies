package main

import rego.v1

test_deny_when_resource_is_deleted if {
  plan := {
    "resource_changes": [
      {
        "address": "aws_s3_bucket.logs",
        "type": "aws_s3_bucket",
        "change": {
          "actions": ["delete"],
          "after": null
        }
      }
    ]
  }

  msg := deny[_] with input as plan
  msg == "Resource scheduled for deletion: aws_s3_bucket.logs"
}

test_deny_when_security_group_allows_world_ssh if {
  plan := {
    "resource_changes": [
      {
        "address": "aws_security_group.web",
        "type": "aws_security_group",
        "change": {
          "actions": ["create"],
          "after": {
            "ingress": [
              {
                "from_port": 22,
                "to_port": 22,
                "cidr_blocks": ["0.0.0.0/0"]
              }
            ]
          }
        }
      }
    ]
  }

  msg := deny[_] with input as plan
  msg == "Security group aws_security_group.web allows SSH from 0.0.0.0/0"
}

test_allow_safe_plan if {
  plan := {
    "resource_changes": [
      {
        "address": "aws_instance.app",
        "type": "aws_instance",
        "change": {
          "actions": ["create"],
          "after": {
            "ami": "ami-1234",
            "instance_type": "t3.micro"
          }
        }
      }
    ]
  }

  count(deny) with input as plan == 0
}
