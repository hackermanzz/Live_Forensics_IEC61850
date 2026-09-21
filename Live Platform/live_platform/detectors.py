from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, List, Optional


class DetectionEngine:
    def __init__(self) -> None:
        self.alerts: List[Dict[str, Any]] = []

    def from_rule_engine(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "source": "rule_engine",
            "protocol": payload.get("protocol", "UNKNOWN"),
            "severity": payload.get("severity", "low"),
            "message": payload.get("message", "Rule-based detection fired"),
            "details": payload.get("details", {}),
        }

    def from_ml_model(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "source": "ml_model",
            "protocol": payload.get("protocol", "UNKNOWN"),
            "severity": payload.get("severity", "low"),
            "message": payload.get("message", "ML detection fired"),
            "details": payload.get("details", {}),
        }


class EnsembleDetector:
    """Two-member protocol ensemble with batch prediction support."""

    def __init__(
        self,
        protocol: str,
        members: Optional[List[Any]] = None,
        artifact_paths: Optional[List[Optional[str]]] = None,
        load_errors: Optional[List[Optional[str]]] = None,
    ) -> None:
        self.protocol = protocol
        self.members = self._pad_to_two(members or [])
        self.artifact_paths = self._pad_to_two(artifact_paths or [])
        self.load_errors = self._pad_to_two(load_errors or [])
        self._executor: ThreadPoolExecutor | None = None

    @classmethod
    def from_joblib_files(cls, protocol: str, paths: List[str | Path | None]) -> "EnsembleDetector":
        members: List[Any | None] = []
        artifact_paths: List[str | None] = []
        load_errors: List[str | None] = []

        for path in cls._pad_to_two(paths):
            if path is None:
                members.append(None)
                artifact_paths.append(None)
                load_errors.append("not_configured")
                continue

            artifact_path = Path(path)
            artifact_paths.append(str(artifact_path))
            if not artifact_path.exists():
                members.append(None)
                load_errors.append("missing_file")
                continue

            try:
                import joblib

                members.append(JoblibModelMember(artifact_path, joblib.load(artifact_path)))
                load_errors.append(None)
            except Exception as exc:
                members.append(None)
                load_errors.append(f"{type(exc).__name__}: {exc}")

        return cls(protocol, members=members, artifact_paths=artifact_paths, load_errors=load_errors)

    @staticmethod
    def _pad_to_two(items: List[Any]) -> List[Any]:
        padded = list(items[:2])
        while len(padded) < 2:
            padded.append(None)
        return padded

    def status(self) -> Dict[str, Any]:
        loaded = [member is not None for member in self.members]
        return {
            "protocol": self.protocol,
            "expected_members": 2,
            "loaded_members": sum(1 for item in loaded if item),
            "ready": all(loaded),
            "members": loaded,
            "artifact_paths": self.artifact_paths,
            "load_errors": self.load_errors,
        }

    def predict(self, features: Dict[str, Any]) -> Dict[str, Any]:
        return self.predict_batch([features])[0]

    def predict_batch(self, features_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if not features_list:
            return []

        active_members = [member for member in self.members if member is not None]
        if not active_members:
            return [self._not_configured_result() for _ in features_list]

        if len(active_members) == 1:
            member_batches = [self._predict_member_batch(active_members[0], features_list)]
        else:
            if self._executor is None:
                self._executor = ThreadPoolExecutor(max_workers=len(active_members))
            member_batches = list(self._executor.map(lambda member: self._predict_member_batch(member, features_list), active_members))

        results: List[Dict[str, Any]] = []
        for index in range(len(features_list)):
            member_results = [batch[index] for batch in member_batches if index < len(batch)]
            results.append(self._combine_member_results(member_results))
        return results

    def _not_configured_result(self) -> Dict[str, Any]:
        return {
            "is_anomaly": False,
            "label": "not_configured",
            "confidence": 0.0,
            "details": {
                "protocol": self.protocol,
                "reason": f"{self.protocol} ensemble has no loaded model members yet",
                "expected_members": 2,
            },
        }

    def _combine_member_results(self, member_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        anomaly_votes = [result for result in member_results if result.get("is_anomaly")]
        ensemble_anomaly = bool(member_results) and len(anomaly_votes) == len(member_results)
        confidence = max((float(result.get("confidence", 0.0)) for result in member_results), default=0.0)
        label = anomaly_votes[0].get("label", "anomaly") if ensemble_anomaly else "normal"
        return {
            "is_anomaly": ensemble_anomaly,
            "label": label,
            "confidence": confidence,
            "severity": "medium" if ensemble_anomaly else "low",
            "message": f"{self.protocol} ensemble anomaly detected" if ensemble_anomaly else f"{self.protocol} ensemble normal",
            "details": {
                "protocol": self.protocol,
                "member_results": member_results,
                "votes_for_anomaly": len(anomaly_votes),
                "members_evaluated": len(member_results),
            },
        }

    def _predict_member_batch(self, member: Any, features_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        try:
            if hasattr(member, "predict_many"):
                return member.predict_many(features_list)
        except Exception:
            pass
        return [self._predict_member(member, features) for features in features_list]

    def _predict_member(self, member: Any, features: Dict[str, Any]) -> Dict[str, Any]:
        try:
            if hasattr(member, "predict_one"):
                prediction = member.predict_one(features)
            elif hasattr(member, "predict"):
                prediction = member.predict(features)
            else:
                prediction = member(features)
        except Exception as exc:
            return {
                "is_anomaly": False,
                "label": "model_error",
                "confidence": 0.0,
                "details": {"error": f"{type(exc).__name__}: {exc}"},
            }
        if not isinstance(prediction, dict):
            prediction = {"is_anomaly": bool(prediction), "label": str(prediction), "confidence": 0.0}
        return prediction


class JoblibModelMember:
    """Adapter for joblib artifacts, including sklearn/xgboost estimators."""

    def __init__(self, path: Path, model: Any) -> None:
        self.path = str(path)
        self.model = model
        self._enable_model_parallelism()
        self._prediction_cache: Dict[Any, Dict[str, Any]] = {}
        self._prediction_cache_limit = 2048

    def _enable_model_parallelism(self) -> None:
        try:
            if hasattr(self.model, "set_params") and "n_jobs" in self.model.get_params():
                self.model.set_params(n_jobs=-1)
            elif hasattr(self.model, "n_jobs"):
                self.model.n_jobs = -1
        except Exception:
            pass

    def predict_one(self, features: Dict[str, Any]) -> Dict[str, Any]:
        return self.predict_many([features])[0]

    def predict_many(self, features_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if not features_list:
            return []
        if hasattr(self.model, "predict_one") or (callable(self.model) and not hasattr(self.model, "predict")):
            return [self._predict_one_uncached(features) for features in features_list]

        results: List[Dict[str, Any] | None] = [None] * len(features_list)
        uncached: List[Dict[str, Any]] = []
        uncached_indexes: List[int] = []
        uncached_keys: List[Any] = []

        for index, features in enumerate(features_list):
            cache_key = self._cache_key(features)
            if cache_key is not None and cache_key in self._prediction_cache:
                results[index] = deepcopy(self._prediction_cache[cache_key])
                continue
            uncached.append(features)
            uncached_indexes.append(index)
            uncached_keys.append(cache_key)

        if uncached:
            try:
                matrix = self._feature_matrix_many(uncached)
                batch_predictions = self._predict_batch_with_estimator(matrix)
            except Exception:
                batch_predictions = [self._predict_one_uncached(features) for features in uncached]

            for index, cache_key, prediction in zip(uncached_indexes, uncached_keys, batch_predictions):
                normalized = self._normalize_prediction(prediction)
                results[index] = normalized
                if cache_key is not None:
                    self._cache_prediction(cache_key, normalized)

        return [
            deepcopy(result) if result is not None else self._predict_one_uncached(features_list[index])
            for index, result in enumerate(results)
        ]

    def _predict_one_uncached(self, features: Dict[str, Any]) -> Dict[str, Any]:
        cache_key = self._cache_key(features)
        if cache_key is not None and cache_key in self._prediction_cache:
            return deepcopy(self._prediction_cache[cache_key])

        if hasattr(self.model, "predict_one"):
            prediction = self.model.predict_one(features)
        elif hasattr(self.model, "predict"):
            prediction = self._predict_with_estimator(features)
        elif callable(self.model):
            prediction = self.model(features)
        else:
            raise TypeError(f"Unsupported joblib model artifact at {self.path}")
        normalized = self._normalize_prediction(prediction)
        if cache_key is not None:
            self._cache_prediction(cache_key, normalized)
        return normalized

    def _cache_prediction(self, cache_key: Any, prediction: Dict[str, Any]) -> None:
        if len(self._prediction_cache) >= self._prediction_cache_limit:
            self._prediction_cache.pop(next(iter(self._prediction_cache)))
        self._prediction_cache[cache_key] = deepcopy(prediction)

    def _predict_with_estimator(self, features: Dict[str, Any]) -> Any:
        matrix = self._feature_matrix(features)
        proba_prediction = self._predict_from_proba(matrix)
        if proba_prediction is not None:
            return proba_prediction

        try:
            prediction = self.model.predict(matrix)
        except Exception:
            prediction = self.model.predict(features)

        confidence = self._prediction_confidence(matrix, prediction)
        if confidence is None:
            return prediction
        value = self._first_value(prediction)
        return {"is_anomaly": bool(value), "label": str(value), "confidence": confidence}

    def _predict_from_proba(self, matrix: Any) -> Dict[str, Any] | None:
        predictions = self._predict_batch_from_proba(matrix)
        if not predictions:
            return None
        return predictions[0]

    def _predict_batch_with_estimator(self, matrix: Any) -> List[Dict[str, Any]]:
        proba_predictions = self._predict_batch_from_proba(matrix)
        if proba_predictions is not None:
            return proba_predictions
        predictions = self.model.predict(matrix)
        if hasattr(predictions, "tolist"):
            predictions = predictions.tolist()
        return [{"is_anomaly": bool(value), "label": str(value), "confidence": 0.0} for value in predictions]

    def _predict_batch_from_proba(self, matrix: Any) -> List[Dict[str, Any]] | None:
        if not hasattr(self.model, "predict_proba"):
            return None
        try:
            probabilities = self.model.predict_proba(matrix)
        except Exception:
            return None
        if hasattr(probabilities, "tolist"):
            probabilities = probabilities.tolist()
        if not probabilities:
            return None
        classes = list(getattr(self.model, "classes_", []))
        predictions: List[Dict[str, Any]] = []
        for row in probabilities:
            if not row:
                return None
            best_index = max(range(len(row)), key=lambda index: row[index])
            label = classes[best_index] if best_index < len(classes) else best_index
            predictions.append({"is_anomaly": bool(label), "label": str(label), "confidence": float(row[best_index])})
        return predictions

    def _feature_matrix(self, features: Dict[str, Any]) -> Any:
        return self._feature_matrix_many([features])

    def _feature_matrix_many(self, features_list: List[Dict[str, Any]]) -> Any:
        feature_names = getattr(self.model, "feature_names_in_", None)
        if feature_names is None:
            return features_list
        names = [str(name) for name in feature_names]
        rows = [{name: features.get(name, 0.0) for name in names} for features in features_list]
        try:
            import pandas as pd

            return pd.DataFrame(rows, columns=names)
        except Exception:
            return [[row[name] for name in names] for row in rows]

    def _prediction_confidence(self, matrix: Any, prediction: Any) -> Optional[float]:
        if not hasattr(self.model, "predict_proba"):
            return None
        try:
            probabilities = self.model.predict_proba(matrix)
        except Exception:
            return None
        if hasattr(probabilities, "tolist"):
            probabilities = probabilities.tolist()
        if not probabilities:
            return None
        row = probabilities[0]
        classes = list(getattr(self.model, "classes_", []))
        value = self._first_value(prediction)
        try:
            class_index = classes.index(value)
        except ValueError:
            try:
                class_index = classes.index(int(value))
            except Exception:
                class_index = len(row) - 1
        try:
            return float(row[class_index])
        except Exception:
            return None

    def _cache_key(self, features: Dict[str, Any]) -> Any:
        feature_names = getattr(self.model, "feature_names_in_", None)
        if feature_names is None:
            return None
        return tuple((str(name), self._cache_value(features.get(str(name), 0.0))) for name in feature_names)

    def _cache_value(self, value: Any) -> Any:
        if isinstance(value, (str, int, float, bool)) or value is None:
            return value
        if hasattr(value, "item"):
            try:
                return value.item()
            except Exception:
                pass
        return str(value)

    def _first_value(self, value: Any) -> Any:
        if isinstance(value, (list, tuple)) and value:
            return value[0]
        if hasattr(value, "tolist"):
            values = value.tolist()
            if isinstance(values, list) and values:
                return values[0]
            return values
        return value

    def _normalize_prediction(self, prediction: Any) -> Dict[str, Any]:
        if isinstance(prediction, dict):
            normalized = dict(prediction)
        else:
            if isinstance(prediction, (list, tuple)) and prediction:
                value = prediction[0]
            elif hasattr(prediction, "tolist"):
                values = prediction.tolist()
                value = values[0] if isinstance(values, list) and values else values
            else:
                value = prediction
            normalized = {"is_anomaly": bool(value), "label": str(value), "confidence": 0.0}
        normalized.setdefault("details", {})
        normalized["details"] = {**(normalized.get("details") or {}), "artifact_path": self.path}
        return normalized


class ProtocolMLRouter:
    def __init__(
        self,
        goose_detector: Optional[EnsembleDetector] = None,
        sv_detector: Optional[EnsembleDetector] = None,
    ) -> None:
        self.detectors = {
            "GOOSE": goose_detector or EnsembleDetector("GOOSE"),
            "SV": sv_detector or EnsembleDetector("SV"),
        }

    @classmethod
    def from_joblib_files(
        cls,
        goose_paths: List[str | Path | None],
        sv_paths: List[str | Path | None],
    ) -> "ProtocolMLRouter":
        return cls(
            goose_detector=EnsembleDetector.from_joblib_files("GOOSE", goose_paths),
            sv_detector=EnsembleDetector.from_joblib_files("SV", sv_paths),
        )

    def status(self) -> Dict[str, Any]:
        return {
            "mode": "protocol_ensembles",
            "order": "rule_based_first_then_protocol_ensemble",
            "parallelism": "ensemble_members_run_in_parallel",
            "artifact_format": "joblib",
            "protocols": {protocol: detector.status() for protocol, detector in self.detectors.items()},
        }

    def predict(self, features: Dict[str, Any]) -> Dict[str, Any]:
        return self.predict_batch([features])[0]

    def predict_batch(self, features_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any] | None] = [None] * len(features_list)
        by_protocol: Dict[str, List[tuple[int, Dict[str, Any]]]] = {}
        for index, features in enumerate(features_list):
            protocol = features.get("protocol")
            detector = self.detectors.get(protocol)
            if detector is None:
                results[index] = {
                    "is_anomaly": False,
                    "label": "unsupported_protocol",
                    "confidence": 0.0,
                    "details": {"reason": f"No ML ensemble configured for protocol {protocol}"},
                }
                continue
            by_protocol.setdefault(protocol, []).append((index, features))

        for protocol, items in by_protocol.items():
            detector = self.detectors[protocol]
            predictions = detector.predict_batch([features for _, features in items])
            for (index, _), prediction in zip(items, predictions):
                results[index] = prediction

        return [result or {
            "is_anomaly": False,
            "label": "unsupported_protocol",
            "confidence": 0.0,
            "details": {"reason": "No ML ensemble configured"},
        } for result in results]


MLDetector = ProtocolMLRouter
