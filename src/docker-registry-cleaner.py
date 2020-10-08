#!/usr/bin/env python3

import logging
from lib.registry import DockerRegistryClient, Repository, Manifest
import json
from datetime import datetime, timedelta, timezone
from dateutil.parser import isoparse
from requests.exceptions import HTTPError
from jsonschema import validate, Draft7Validator, ValidationError
import yaml
import re
from argparse import ArgumentError
from typing import Dict, List, Tuple, Union
import sys
from prometheus_client import CollectorRegistry, Counter, Gauge, push_to_gateway
import os.path

try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader

from lib.config import Config, Argument

RULES_SCHEMA = {
    "type": "object",
    "properties": {
        "rules": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "repoRegExp": {
                        "type": "string",
                        "format": "regex"
                    },
                    "tags": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "oneOf": [
                                {
                                    "properties": {
                                        "tagRegExp": {
                                            "type": "string",
                                            "format": "regex"
                                        },
                                        "last": {
                                            "type": "number",
                                        },
                                        "name": {
                                            "type": "string"
                                        },
                                    },
                                    "required": ["tagRegExp", "last"],
                                    "additionalProperties": False,
                                },
                                {
                                    "properties": {
                                        "tagRegExp": {
                                            "type": "string",
                                            "format": "regex"
                                        },
                                        "maxAge": {
                                            "anyOf": [
                                                {
                                                    "type": "string",
                                                    "pattern": "^([0-9]+w)?([0-9]+d)?([0-9]+h)?([0-9]+m)?([0-9]+s)?$"
                                                },
                                                {
                                                    "type": "number"
                                                }
                                            ]
                                        },
                                        "last": {
                                            "type": "number"
                                        },
                                        "name": {
                                            "type": "string"
                                        },
                                    },
                                    "required": ["tagRegExp", "maxAge"],
                                    "additionalProperties": False,
                                },
                                {
                                    "properties": {
                                        "tagRegExp": {
                                            "type": "string",
                                            "format": "regex"
                                        },
                                        "keep": {
                                            "type": "boolean"
                                        },
                                        "name": {
                                            "type": "string"
                                        }
                                    },
                                    "required": ["tagRegExp", "keep"],
                                    "additionalProperties": False,
                                },
                            ]
                        }
                    }
                },
                "additionalProperties": False
            }
        }
    },
    "additionalProperties": False
}


def process_config() -> None:
    """
    Process configuration and prepare rules.
    """

    cfg = Config([
        Argument("registry_url", str, "Docker registry URL to work with.", default="http://localhost:5000/"),
        Argument("registry_validate_ssl", bool, "Whether to validate SSL certificate of registry", default=True),
        Argument("rules_configuration_file", str, "Load rules specification from file", default="rules.yaml"),
        Argument("pushgateway_url", str, "Prometheus Pushgateway URL to push metrics about untagged tags.", default=None),
        Argument("job_name", str, "Job name for metrics.", default=os.path.splitext(os.path.basename(__file__))[0]),
        Argument("dry_run", bool, "Set to true to actually do not delete anything, just print what sould be done", default=False)
    ])

    logging.getLogger("urllib3.connectionpool").setLevel(logging.INFO)
    logging.getLogger("DockerRegistryClient").setLevel(logging.INFO)

    logging.info("Loading rules from {}.".format(cfg.rules_configuration_file))
    rules = yaml.load(open(cfg.rules_configuration_file, "r"), Loader=Loader)

    # Validate tag configs agains schema.
    try:
        validate(instance=rules, schema=RULES_SCHEMA, cls=Draft7Validator)
    except ValidationError as e:
        logging.error("Rules configuration is not valid: At ${}: {}".format("".join(map(lambda x: "[" + str(x) + "]" if isinstance(x, int) else "." + x, e.absolute_path)), e))
        sys.exit(1)

    logging.debug("Loaded rules: {}".format(rules))

    cfg.rules = rules["rules"]
    cfg.cli = DockerRegistryClient(cfg.registry_url, verify_ssl=cfg.registry_validate_ssl)
    
    if cfg.pushgateway_url:
        cfg.prom_registry = CollectorRegistry()
    else:
        cfg.prom_registry = None

    return cfg


def gather_tags(repository: Repository, rules: List[dict]) -> Dict[str, List[Tuple[str, Manifest]]]:
    """
    Gather tags from repository and split them by rule.
    :param repository: Repository that is being processed
    :param rules: Rules applicable to this repository.
    :return: Tags splitted by rule. Each dict key contains list of tuples (tag, manifest).
    """

    logging.debug("Loading tags...")

    tags_by_re = {}
    tags = repository.tags()

    if not tags:
        logging.warning("There are no tags in repository {}.".format(repository.name))
        return tags_by_re

    logging.debug("Got {} tags, sorting and fetching manifests.".format(len(tags)))

    for tag in tags:
        tag_rule = None
        for rule in rules:
            if re.match(rule["tagRegExp"], tag):
                tag_rule = rule
                break

        if not tag_rule:
            logging.debug("Tag {} in repository {} does not match any rule. Skipping...".format(tag, repository.name))
            continue

        manifest = repository.manifest(tag)
        tags_by_re.setdefault(tag_rule["tagRegExp"], []).append((tag, manifest))

    logging.debug("Got tags fetched and sorted by rules.")

    return tags_by_re


def sort_by_date(tags: List[Tuple[str, Manifest]]) -> List[Tuple[str, Manifest]]:
    """
    Sort tags by date and return it as ordered list.
    :param tags: Tags to be sorted (list of tuples (tag, manifest))
    :return: Tags sorted by date (list of tuples (tag, manifest) sorted by manifest create date)
    """
    return sorted(tags, key=lambda x: x[1].created, reverse=True)


def parse_max_age(max_age: Union[str, int]) -> timedelta:
    """
    Parse max_age in form 14d5h3m1s to timedelta object. If max_age is int, consider it as number of seconds.
    """

    if isinstance(max_age, int):
        return timedelta(seconds=max_age)

    kwargs = {}

    for amount, unit in re.findall("([0-9]+)([wdhms])", max_age):
        kwarg = {
            "w": "weeks",
            "d": "days",
            "h": "hours",
            "m": "minutes",
            "s": "seconds"
        }[unit]

        kwargs[kwarg] = int(amount)

    return timedelta(**kwargs)


def remove_manifests(repository: Repository, manifestlist: List[Manifest], removed: Counter, failed: Counter,
    dry_run: bool) -> bool:
    """
    Remove manifests that should be removed.
    :param repository: Repository we are working with
    :param manifestlist: List of tags to untag
    :param untagged: Metric to increment for successfully untagged tags.
    :param failed: Metric to increment when untagging fails.
    :param dry_run: Do not delete anything, just print what would be done.
    :returns bool: Whether the operation has completed successfully.
    """

    resp = True
    for manifest in manifestlist:
        try:
            if not dry_run:
                logging.debug("Removing manifest {} in repository {}. Affected tags: {}".format(manifest.digest, repository.name, ", ".join(manifest.references)))
                manifest.delete()
            else:
                logging.warning("Would remove manifest {} in repository {} if dry run was not enabled. Affected tags: {}".format(manifest.digest, repository.name, ", ".join(manifest.references)))

            removed.inc()
        except HTTPError as e:
            failed.inc()
            logging.error("When talking to registry: {}".format(e))
            resp = False

    return resp


def process_tags(repository: Repository, rules: List[dict], tags_by_re: Dict[str, List[Tuple[str, Manifest]]],
    kept_metric: Counter, removed_metric: Counter, failed_metric: Counter, dry_run: bool) -> bool:
    """
    Process gathered tags acording to rules.
    :param repository: Repository we are working with
    :param rules: List of rules that should be applied on this repository.
    :param tags_by_re: Tags divided by individual rules.
    :param kept_metric: Metric to increment when tag has been kept back.
    :param removed_metric: Metric to increment when tag has been untagged.
    :param failed_metric: Metric to increment when untagging has failed.
    :param dry_run: Do not delete anything, just print what would be done.
    :return: Whether the processing was successfull.
    """

    all_manifests = set()
    manifests_to_keep = set()

    result = True
    for rule in rules:
        tags = tags_by_re.get(rule["tagRegExp"])

        if not tags:
            # No tags match this RE, proceed.
            continue

        tags = sort_by_date(tags)

        for tag, manifest in tags:
            all_manifests.add(manifest)

        rule_name = rule.get("name", rule["tagRegExp"])

        if "keep" in rule:
            # all = False means all tags are cleared
            # all = True means do not clear any tag
            if rule["keep"]:
                logging.info("For {}: Keeping all tags, because keep is True.".format(rule_name))
                for tag, manifest in tags:
                    logging.info("Keeping tag {}.".format(tag))
                    manifests_to_keep.add(manifest)

        elif "maxAge" in rule:
            # keep only tags newer than maxAge interval.
            duration = parse_max_age(rule["maxAge"])
            threshold = datetime.now(timezone.utc) - duration

            if "last" in rule:
                to_keep = tags[0:rule["last"]]
                logging.info("For {}: Keeping only tags newer than {}, but keeping last {} tag(s).".format(
                    rule_name,
                    threshold,
                    rule["last"],
                ))

                for tag, manifest in to_keep:
                    logging.info("Keeping {} (created {}) as it is one of newest.".format(tag, manifest.created))
                    manifests_to_keep.add(manifest)
            else:
                logging.info("For {}: Keeping only tags newer than {}.".format(rule_name, threshold))

            for tag, manifest in tags[rule.get("last", 0):]:
                if manifest.created >= threshold:
                    logging.info("Keeping tag {} (created {}).".format(tag, manifest.created))
                    manifests_to_keep.add(manifest)

        elif "last" in rule:
            # keep only last <num> of tags, untag the rest
            to_keep = tags[0:rule["last"]]
            logging.info("For {}: Keeping only last {} tag(s).".format(
                rule_name,
                rule["last"]
            ))

            for tag, manifest in to_keep:
                logging.info("Keeping {} (created {}).".format(tag, manifest.created))
                manifests_to_keep.add(manifest)

    kept = kept_metric.labels(repository=repository.name)
    removed = removed_metric.labels(repository=repository.name)
    failed = failed_metric.labels(repository=repository.name)

    remove_manifests(repository, all_manifests - manifests_to_keep, removed, failed, dry_run=dry_run)
    kept.inc(len(manifests_to_keep))

    return result


def main():
    cfg = None
    try:
        cfg = process_config()

        success_gauge = Gauge('success', 'Whether the execution was successfull.', registry=cfg.prom_registry)
        success_gauge.set(0)
        
        result = True

        try:
            logging.debug("Loading repositories...")

            kept_tags_metric = Counter("kept_tags", "Number of tags that has been kept back.", ("repository", ), registry=cfg.prom_registry)
            removed_metric = Counter("removed_tags", "Number of tags that has been purged.", ("repository", ), registry=cfg.prom_registry)
            failed_metric = Counter("failed_tags", "Number of tags that should be removed, but that operation has failed.", ("repository", ), registry=cfg.prom_registry)

            repositories = cfg.cli.repositories()
            for repository in repositories:
                repo_rules = None
                for repo_spec in cfg.rules:
                    if re.match(repo_spec["repoRegExp"], repository.name):
                        repo_rules = repo_spec["tags"]
                        break

                if not repo_rules:
                    logging.debug("Repository {} does not have rule. skipping...".format(repository.name))
                    continue

                logging.info("Processing repository {}...".format(repository.name))
                logging.debug("Rules: {}".format(repo_rules))

                try:
                    tags_by_re = gather_tags(repository, repo_rules)
                    result = result and process_tags(
                        repository, repo_rules, tags_by_re,
                        kept_tags_metric,
                        removed_metric,
                        failed_metric,
                        dry_run=cfg.dry_run
                    )
                except HTTPError as e:
                    logging.error("When processing repository {}: {}".format(repository.name, e))
                    result = False

                logging.info("Done processing repository {}.".format(repository.name))
        except HTTPError as e:
            logging.error("Unable to load repositories from registry: {}".format(e))
            result = False    
        
        if not result:
            logging.error("There was an error while processing repositories. Examine log.")
            sys.exit(1)
        else:
            success_gauge.set(1)
    except Exception as e:
        logging.exception(e)
    finally:
        # Push metrics to pushgateway if configured.
        if cfg and cfg.prom_registry:
            logging.debug("Pushing metrics:")
            
            for metric in cfg.prom_registry.collect():
                for sample in metric.samples:
                    if sample.labels:
                        logging.debug("    {}{{{}}} = {}".format(sample.name, ",".join(["{}=\"{}\"".format(key, val) for key, val in sample.labels.items()]), sample.value))
                    else:
                        logging.debug("    {} = {}".format(sample.name, sample.value))

            if not cfg.dry_run:
                try:
                    logging.debug("Pushing metrics to {} with job={}.".format(cfg.pushgateway_url, cfg.job_name))
                    push_to_gateway(cfg.pushgateway_url, job=cfg.job_name, registry=cfg.prom_registry)
                except Exception as e:
                    logging.exception("While pushing metrics: {}".format(e))
                    sys.exit(1)
        else:
            logging.debug("Skipping pushing metrics, as Pushgateway is not configured.")
    
        logging.info("All done.")


if __name__ == "__main__":
    main()
