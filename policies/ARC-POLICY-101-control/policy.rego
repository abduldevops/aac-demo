package policies.architecture.aac_101

default deny = []

# Microservices must be defined within a system boundary labeled 'Fargate' or 'ECS'
deny[msg] {
  container := input.containers[_]
  not startswith(container.boundary, "ecs")  # assumes ECS cluster boundaries use 'ecs' prefix
  msg := sprintf("Container '%s' must be deployed in ECS Fargate (boundary not ECS)", [container.alias])
}
