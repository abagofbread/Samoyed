from __future__ import annotations

from samoyed.cloud.concepts import CloudProvider
from samoyed.enumerators.aws import AWS_ENUMERATORS
from samoyed.enumerators.azure import AZURE_ENUMERATORS
from samoyed.enumerators.gcp import GCP_ENUMERATORS
from samoyed.enumerators.k8s import K8S_ENUMERATORS
from samoyed.enumerators.contracts import ConceptEnumerator
from samoyed.enumerators.runner import EnumeratorRunner
from samoyed.extensions.discovery import discover_enumerators


def get_runner(provider: CloudProvider) -> EnumeratorRunner:
    if provider == CloudProvider.AWS:
        enums: list[ConceptEnumerator] = list(AWS_ENUMERATORS)
        enums.extend(discover_enumerators())
        return EnumeratorRunner(enums)
    if provider == CloudProvider.KUBERNETES:
        enums = list(K8S_ENUMERATORS)
        enums.extend(discover_enumerators())
        return EnumeratorRunner(enums)
    if provider == CloudProvider.GCP:
        enums = list(GCP_ENUMERATORS)
        enums.extend(discover_enumerators())
        return EnumeratorRunner(enums)
    if provider == CloudProvider.AZURE:
        enums = list(AZURE_ENUMERATORS)
        enums.extend(discover_enumerators())
        return EnumeratorRunner(enums)
    raise ValueError(f"Unsupported provider: {provider}")
