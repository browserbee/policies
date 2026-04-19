package main

import rego.v1

input_obj := input if is_object(input) else := {}

has_resource_changes if {
  object.get(input_obj, "resource_changes", null) != null
}

deny contains msg if {
  has_resource_changes
  resource_change := input.resource_changes[_]
  is_pure_delete(resource_change.change.actions)
  msg := sprintf("Resource scheduled for deletion: %s", [resource_change.address])
}

deny contains msg if {
  has_resource_changes
  resource_change := input.resource_changes[_]
  resource_change.type == "aws_security_group"
  after := resource_change.change.after
  after != null
  ingress := object.get(after, "ingress", [])[_]
  cidr := object.get(ingress, "cidr_blocks", [])[_]
  cidr == "0.0.0.0/0"
  from_port := to_number(object.get(ingress, "from_port", -1))
  to_port := to_number(object.get(ingress, "to_port", -1))
  from_port <= 22
  to_port >= 22
  msg := sprintf("Security group %s allows SSH from 0.0.0.0/0", [resource_change.address])
}

deny contains msg if {
  has_resource_changes
  resource_change := input.resource_changes[_]
  resource_change.type == "aws_security_group_rule"
  after := resource_change.change.after
  after != null
  lower(object.get(after, "type", "")) == "ingress"
  cidr := object.get(after, "cidr_blocks", [])[_]
  cidr == "0.0.0.0/0"
  from_port := to_number(object.get(after, "from_port", -1))
  to_port := to_number(object.get(after, "to_port", -1))
  from_port <= 22
  to_port >= 22
  msg := sprintf("Security group rule %s allows SSH from 0.0.0.0/0", [resource_change.address])
}

is_pure_delete(actions) if {
  some idx
  actions[idx] == "delete"
  not action_has_create(actions)
}

action_has_create(actions) if {
  some idx
  actions[idx] == "create"
}
