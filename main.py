import yaml
import os

# Prefix for project label
prefix = ""
# An absolute path, example: /Users/user/repository
root_path = ""
# A relative path, example: apps
apps_path = "apps"
# Scanners that you'd like to deploy
scanners = [
    "boostsecurityio/semgrep",
    "boostsecurityio/gitleaks",
    "boostsecurityio/trivy-fs",
    "boostsecurityio/trivy-sbom",
    "boostsecurityio/checkov",
]

##################
yaml_file_path = ".gitlab.yml"

with open(yaml_file_path, "r") as yaml_file:
    data = yaml.safe_load(yaml_file)


def get_projects(path, apps_path):
    """
    Get projects located in a monorepo

    Args:
    path (str): Absolute path of root directory where search will take place.
    apps_path (str): Path relative of root directory where search will take place.

    Returns:
    list: List of projects.
    """
    projects = []
    path = os.path.join(path, apps_path)
    # Ensure the path exists and is a directory
    if os.path.exists(path) and os.path.isdir(path):
        # Get a list of all items in the directory
        items = os.listdir(path)
        projects = [
            {"project_path": f"{apps_path}/{item}", "project_label": f"{prefix}-item"}
            for item in items
            if os.path.isdir(os.path.join(path, item)) and not item.startswith(".")
        ]
    return projects


projects = get_projects(root_path, apps_path)

for project in projects:
    for scanner in scanners:
        scanner_name = scanner.split("/")[1]
        rules = [{"changes": [f"{project['project_path']}/*"]}]
        if scanner_name == "trivy-sbom":
            rules.append({"if": "$CI_COMMIT_BRANCH == $DEFAULT_BRANCH"})
        data[f"boost-{scanner_name}-{project['project_path']}"] = {
            "stage": "build",
            "extends": [".boost_scan"],
            "variables": {
                "BOOST_SCANNER_REGISTRY_MODULE": scanner,
                "BOOST_API_TOKEN": "$BOOST_API_TOKEN",
                "BOOST_SCAN_LABEL": project["project_label"],
                "BOOST_SCAN_PATH": f"{project['project_path']}/",
            },
            "rules": rules,
        }


with open("output.yml", "w") as yaml_file:
    yaml.dump(data, yaml_file, default_flow_style=False)
