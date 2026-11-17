# Two images: the proxy (deploy/Dockerfile) and the classifier with its model
# baked in (deploy/classifier, BAKE_MODEL=true). Tags are immutable: each
# deploy pushes sha-<commit>, so every task definition revision names exactly
# one image and a rollback is "use the previous revision".

locals {
  repositories = toset(["proxy", "classifier"])
}

resource "aws_ecr_repository" "app" {
  for_each             = local.repositories
  name                 = "${local.name}-${each.key}"
  image_tag_mutability = "IMMUTABLE"
  force_delete         = var.ephemeral

  image_scanning_configuration {
    scan_on_push = true
  }
}

resource "aws_ecr_lifecycle_policy" "app" {
  for_each   = local.repositories
  repository = aws_ecr_repository.app[each.key].name
  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Keep the 20 most recent images (enough to roll back)"
      selection = {
        tagStatus   = "any"
        countType   = "imageCountMoreThan"
        countNumber = 20
      }
      action = { type = "expire" }
    }]
  })
}
