from __future__ import annotations

from samoyed.enumerators.k8s.cloud_binding import K8sCloudBindingEnumerator
from samoyed.enumerators.k8s.nodes import K8sNodeEnumerator
from samoyed.enumerators.k8s.rbac import K8sIdentityEnumerator, K8sRbacEnumerator
from samoyed.enumerators.k8s.scope import K8sScopeEnumerator
from samoyed.enumerators.k8s.secrets import K8sSecretEnumerator
from samoyed.enumerators.k8s.workloads import K8sWorkloadEnumerator

K8S_ENUMERATORS = [
    K8sScopeEnumerator(),
    K8sIdentityEnumerator(),
    K8sRbacEnumerator(),
    K8sNodeEnumerator(),
    K8sWorkloadEnumerator(),
    K8sCloudBindingEnumerator(),
    K8sSecretEnumerator(),
]
