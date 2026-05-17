# -*- coding: utf-8 -*-
"""
export_v2_model.py — Train on realistic_logs_v2 and export production artifacts
=============================================================================
1. Loads realistic_network_logs.csv + realistic_user_profiles.csv
2. Engineers v2 features (46 features)
3. Trains Weighted Ensemble (XGB, LGBM, RF, GB) with SMOTE
4. Exports artifacts to hp/model_output/
5. Exports 5000 test events and user profiles as JSON for frontend streaming
6. Logs all parameters, metrics, and artifacts to MLflow
"""

import pandas as pd
import numpy as np
import warnings
import os
import sys
import json
import joblib
import time

from imblearn.over_sampling import SMOTE
from xgboost import XGBClassifier
from lightgbm import LGBMClassifier
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.metrics import (
    precision_recall_curve, f1_score, accuracy_score,
    precision_score, recall_score, roc_auc_score,
    classification_report, confusion_matrix
)
from sklearn.preprocessing import LabelEncoder

import mlflow
import mlflow.sklearn
import mlflow.xgboost

warnings.filterwarnings('ignore')

# ── CONFIG ──────────────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "dataset")
OUTPUT_DIR = os.path.join(BASE_DIR, "model_output")
os.makedirs(OUTPUT_DIR, exist_ok=True)

LOGS_FILE = os.path.join(DATA_DIR, 'updated_realistic_network_logs.csv')
PROFILES_FILE = os.path.join(DATA_DIR, 'updated_realistic_user_profiles.csv')

# MLflow configuration
MLFLOW_TRACKING_URI = os.getenv("MLFLOW_TRACKING_URI", f"file:///{os.path.join(BASE_DIR, 'mlruns').replace(os.sep, '/')}")
MLFLOW_EXPERIMENT_NAME = os.getenv("MLFLOW_EXPERIMENT_NAME", "HPE-Threat-Detection-v2")


def main():
    print("=" * 70)
    print("  EXPORT V2 PIPELINE ARTIFACTS (MLflow Tracked)")
    print("=" * 70)

    # ── MLflow Setup ──
    mlflow.set_tracking_uri(MLFLOW_TRACKING_URI)
    mlflow.set_experiment(MLFLOW_EXPERIMENT_NAME)
    print(f"\n  MLflow Tracking URI : {MLFLOW_TRACKING_URI}")
    print(f"  MLflow Experiment   : {MLFLOW_EXPERIMENT_NAME}")

    with mlflow.start_run(run_name="ensemble-training") as run:
        run_id = run.info.run_id
        print(f"  MLflow Run ID       : {run_id}\n")

        train_start_time = time.time()

        # ── 1. Load Data ──
        print("[1/7] Loading data...")
        if not os.path.exists(LOGS_FILE) or not os.path.exists(PROFILES_FILE):
            sys.exit(f"ERROR: Datasets not found at {DATA_DIR}")
            
        df_logs = pd.read_csv(LOGS_FILE)
        df_profiles = pd.read_csv(PROFILES_FILE)

        # Log dataset metadata
        mlflow.log_param("dataset_logs_file", os.path.basename(LOGS_FILE))
        mlflow.log_param("dataset_profiles_file", os.path.basename(PROFILES_FILE))
        mlflow.log_param("dataset_logs_rows", len(df_logs))
        mlflow.log_param("dataset_profiles_rows", len(df_profiles))

        df_logs['timestamp'] = pd.to_datetime(df_logs['timestamp'])
        df_logs = df_logs.sort_values(by=['user_id', 'timestamp']).reset_index(drop=True)
        df = df_logs.merge(df_profiles, on='user_id', how='left')

        # ── 2. Feature Engineering ──
        print("[2/7] Engineering features...")
        df['hour'] = df['timestamp'].dt.hour
        df['day_of_week'] = df['timestamp'].dt.dayofweek
        df['is_weekend'] = (df['day_of_week'] >= 5).astype(int)
        df['is_night'] = ((df['hour'] < 6) | (df['hour'] > 22)).astype(int)

        time_diff = abs(df['login_hour'] - df['base_login_hour'])
        df['login_time_deviation'] = time_diff.apply(lambda x: min(x, 24 - x))
        df['login_deviation_zscore'] = df['login_time_deviation'] / (df['login_hour_std_dev'] + 0.1)
        df['login_deviation_squared'] = df['login_time_deviation'] ** 2
        df['extreme_time_deviation'] = (df['login_deviation_zscore'] > 2.5).astype(int)

        df['hour_sin'] = np.sin(2 * np.pi * df['hour'] / 24)
        df['hour_cos'] = np.cos(2 * np.pi * df['hour'] / 24)

        typical_start, typical_end = 6, 20
        df['outside_business_hours'] = ((df['hour'] < typical_start) | (df['hour'] > typical_end)).astype(int)
        df['non_tech_off_hours'] = ((df['outside_business_hours'] == 1) & (~df['role'].isin(['Admin', 'Developer']))).astype(int)
        df['deep_night'] = ((df['hour'] >= 1) & (df['hour'] <= 5)).astype(int)

        df['shift_worker_int'] = df['is_shift_worker'].astype(int) if 'is_shift_worker' in df.columns else 0
        df['off_hours_non_shift'] = ((df['outside_business_hours'] == 1) & (df['shift_worker_int'] == 0)).astype(int)

        df['geo_mismatch_int'] = df['geo_mismatch'].astype(int)
        df['impossible_travel_int'] = df['impossible_travel'].astype(int)

        if 'home_region' in df.columns:
            df['from_home_region'] = (df['ip_region'] == df['home_region']).astype(int)
        else:
            df['from_home_region'] = (df['ip_region'] == df['user_region']).astype(int)

        df['download_deviation'] = df['data_downloaded_mb'] - df['avg_daily_downloads_mb']
        df['download_ratio'] = df['data_downloaded_mb'] / (df['avg_daily_downloads_mb'] + 0.01)
        df['download_deviation_abs'] = df['download_deviation'].abs()
        df['is_extreme_download'] = (df['download_ratio'] > 5).astype(int)

        df['has_failed_attempts'] = (df['failed_attempts_last_15m'] > 0).astype(int)
        df['high_failed_attempts'] = (df['failed_attempts_last_15m'] >= 5).astype(int)
        df['very_high_failed'] = (df['failed_attempts_last_15m'] >= 8).astype(int)
        df['success_int'] = df['success'].astype(int)

        df = df.sort_values(by=['user_id', 'timestamp']).reset_index(drop=True)

        first_ip = df.groupby(['user_id', 'source_ip'])['timestamp'].min().reset_index(name='first_seen_ip')
        df = df.merge(first_ip, on=['user_id', 'source_ip'])
        df['is_new_ip'] = (df['timestamp'] == df['first_seen_ip']).astype(int)

        df['prev_ip'] = df.groupby('user_id')['source_ip'].shift(1)
        df['ip_changed'] = ((df['prev_ip'] != df['source_ip']) & df['prev_ip'].notna()).astype(int)

        df['ip_hops_30m'] = df.groupby('user_id', sort=False).rolling('30min', on='timestamp')['ip_changed'].sum().reset_index(drop=True)

        df['is_admin_action'] = (df['action'] == 'admin').astype(int)
        df['admin_actions_15m'] = df.groupby('user_id', sort=False).rolling('15min', on='timestamp')['is_admin_action'].sum().reset_index(drop=True)

        df['failed_action'] = (1 - df['success_int'])
        df['failed_30m'] = df.groupby('user_id', sort=False).rolling('30min', on='timestamp')['failed_action'].sum().reset_index(drop=True)

        df['time_since_last'] = df.groupby('user_id')['timestamp'].diff().dt.total_seconds().fillna(0)
        df['rapid_succession'] = (df['time_since_last'] < 60).astype(int)

        df['event_flag'] = 1
        df['events_1h'] = df.groupby('user_id', sort=False).rolling('60min', on='timestamp')['event_flag'].sum().reset_index(drop=True)

        role_risk = {'Admin': 4, 'Developer': 3, 'Finance': 2, 'HR': 1, 'Sales': 1}
        df['role_risk_score'] = df['role'].map(role_risk).fillna(1)
        df['remote_worker_int'] = df['remote_worker'].astype(int)

        df['admin_non_admin_role'] = ((df['is_admin_action'] == 1) & (df['role'] != 'Admin')).astype(int)
        df['high_download_non_dev'] = ((df['download_ratio'] > 3) & (df['role'] != 'Developer')).astype(int)
        df['geo_not_travel'] = ((df['geo_mismatch_int'] == 1) & (df['impossible_travel_int'] == 0)).astype(int)
        df['geo_and_travel'] = ((df['geo_mismatch_int'] == 1) & (df['impossible_travel_int'] == 1)).astype(int)

        label_encoders = {}
        cat_cols = ['action', 'ip_region', 'user_region', 'role']
        for col in cat_cols:
            le = LabelEncoder()
            df[f'{col}_encoded'] = le.fit_transform(df[col].astype(str))
            label_encoders[col] = le

        # ── 3. Split Data ──
        print("[3/7] Splitting data...")
        y = df['is_injected_anomaly'].astype(int)
        
        drop_cols = [
            'event_id', 'timestamp', 'user_id', 'workspace_id', 'source_ip',
            'is_injected_anomaly', 'anomaly_type', 'first_seen_ip', 'prev_ip',
            'geo_mismatch', 'impossible_travel', 'success', 'remote_worker',
            'action', 'ip_region', 'user_region', 'role',
            'base_login_hour', 'login_hour_std_dev', 'avg_daily_downloads_mb',
            'clumsiness_factor', 'num_known_devices',
            'event_flag', 'ip_changed', 'is_admin_action', 'failed_action',
            'home_region', 'travel_probability', 'is_shift_worker',
        ]

        feature_cols = [c for c in df.columns if c not in drop_cols]
        X = df[feature_cols].copy().fillna(0)

        df_sorted = df.sort_values('timestamp').reset_index(drop=True)
        X = X.loc[df_sorted.index]
        y = y.loc[df_sorted.index]

        split_ratio = 0.80
        split_idx = int(len(X) * split_ratio)
        X_train, X_test = X.iloc[:split_idx], X.iloc[split_idx:]
        y_train, y_test = y.iloc[:split_idx], y.iloc[split_idx:]

        print(f"  Train: {X_train.shape[0]:,} | Test: {X_test.shape[0]:,}")

        # Log split info
        mlflow.log_param("train_test_split_ratio", split_ratio)
        mlflow.log_param("n_features", len(feature_cols))
        mlflow.log_param("train_size", X_train.shape[0])
        mlflow.log_param("test_size", X_test.shape[0])
        mlflow.log_param("anomaly_rate_train", float(y_train.mean()))
        mlflow.log_param("anomaly_rate_test", float(y_test.mean()))

        # ── 4. Export Test Events JSON ──
        print("[4/7] Exporting test events & profiles...")
        
        # Export profiles
        profiles_dict = df_profiles.to_dict('records')
        profiles_path = os.path.join(OUTPUT_DIR, "user_profiles.json")
        with open(profiles_path, "w", encoding="utf-8") as f:
            json.dump(profiles_dict, f, indent=2, default=str)
        
        # Export test events (raw format, pre-feature engineering, to stream to the pipeline)
        test_events_df = df_logs.sort_values('timestamp').iloc[split_idx:].copy()
        test_events_df['timestamp'] = test_events_df['timestamp'].dt.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        # Fix NaN anomaly_type — normal events have NaN which breaks JSON
        test_events_df['anomaly_type'] = test_events_df['anomaly_type'].fillna('None')
        test_events_df = test_events_df.fillna('')
        
        test_events = test_events_df.to_dict('records')
        test_events_path = os.path.join(OUTPUT_DIR, "test_events.json")
        with open(test_events_path, "w", encoding="utf-8") as f:
            json.dump(test_events, f, indent=2, default=str)
            
        print(f"  Exported {len(test_events)} test events.")

        # ── 5. SMOTE ──
        print("[5/7] SMOTE oversampling...")
        smote_strategy = 0.3
        smote_random_state = 42
        smote = SMOTE(sampling_strategy=smote_strategy, random_state=smote_random_state)
        X_train_res, y_train_res = smote.fit_resample(X_train, y_train)

        mlflow.log_param("smote_strategy", smote_strategy)
        mlflow.log_param("smote_random_state", smote_random_state)
        mlflow.log_param("train_size_after_smote", X_train_res.shape[0])

        # ── 6. Train Models ──
        print("[6/7] Training models...")
        
        # --- XGBoost ---
        xgb_params = {
            "n_estimators": 500, "max_depth": 6, "learning_rate": 0.05,
            "subsample": 0.8, "colsample_bytree": 0.8, "min_child_weight": 3,
            "scale_pos_weight": len(y_train_res[y_train_res==0]) / max(len(y_train_res[y_train_res==1]), 1),
            "reg_alpha": 0.1, "reg_lambda": 1.0, "eval_metric": "aucpr",
            "random_state": 42, "use_label_encoder": False, "verbosity": 0,
        }
        xgb_model = XGBClassifier(**xgb_params)
        xgb_model.fit(X_train_res, y_train_res, eval_set=[(X_test, y_test)], verbose=False)
        
        # Log XGBoost params
        for k, v in xgb_params.items():
            mlflow.log_param(f"xgb_{k}", v)
        
        # --- LightGBM ---
        lgbm_params = {
            "n_estimators": 500, "max_depth": 6, "learning_rate": 0.05,
            "subsample": 0.8, "colsample_bytree": 0.8, "min_child_samples": 10,
            "reg_alpha": 0.1, "reg_lambda": 1.0, "is_unbalance": True,
            "random_state": 42, "verbose": -1,
        }
        lgbm_model = LGBMClassifier(**lgbm_params)
        lgbm_model.fit(X_train_res, y_train_res, eval_set=[(X_test, y_test)], 
                       callbacks=[__import__('lightgbm').log_evaluation(0)])

        for k, v in lgbm_params.items():
            mlflow.log_param(f"lgbm_{k}", v)

        # --- Random Forest ---
        rf_params = {
            "n_estimators": 300, "max_depth": 10, "min_samples_leaf": 5,
            "class_weight": "balanced", "random_state": 42, "n_jobs": 1,
        }
        rf_model = RandomForestClassifier(**rf_params)
        rf_model.fit(X_train_res, y_train_res)

        for k, v in rf_params.items():
            mlflow.log_param(f"rf_{k}", v)

        # --- Gradient Boosting ---
        gb_params = {
            "n_estimators": 200, "max_depth": 5, "learning_rate": 0.05,
            "subsample": 0.8, "min_samples_leaf": 10, "random_state": 42,
        }
        gb_model = GradientBoostingClassifier(**gb_params)
        gb_model.fit(X_train_res, y_train_res)

        for k, v in gb_params.items():
            mlflow.log_param(f"gb_{k}", v)

        # ── 7. Optimizing and Exporting ──
        print("[7/7] Optimizing threshold & exporting...")
        
        prob_xgb = xgb_model.predict_proba(X_test)[:, 1]
        prob_lgbm = lgbm_model.predict_proba(X_test)[:, 1]
        prob_rf = rf_model.predict_proba(X_test)[:, 1]
        prob_gb = gb_model.predict_proba(X_test)[:, 1]

        # Weighted ensemble
        weights = {'xgb': 0.35, 'lgbm': 0.30, 'rf': 0.20, 'gb': 0.15}
        ensemble_proba = (weights['xgb'] * prob_xgb) + (weights['lgbm'] * prob_lgbm) + \
                         (weights['rf'] * prob_rf) + (weights['gb'] * prob_gb)

        # Log ensemble weights
        for model_name, weight in weights.items():
            mlflow.log_param(f"ensemble_weight_{model_name}", weight)

        precisions, recalls, thresholds = precision_recall_curve(y_test, ensemble_proba)
        f1_scores = 2 * (precisions * recalls) / (precisions + recalls + 1e-8)
        best_idx = np.argmax(f1_scores)
        best_threshold = float(thresholds[best_idx]) if best_idx < len(thresholds) else 0.5
        
        print(f"  Best F1: {f1_scores[best_idx]:.4f} at Threshold: {best_threshold:.4f}")

        # ── Compute per-model and ensemble metrics ──
        ensemble_preds = (ensemble_proba >= best_threshold).astype(int)
        
        # Ensemble metrics
        ensemble_metrics = {
            "ensemble_f1": f1_score(y_test, ensemble_preds),
            "ensemble_accuracy": accuracy_score(y_test, ensemble_preds),
            "ensemble_precision": precision_score(y_test, ensemble_preds, zero_division=0),
            "ensemble_recall": recall_score(y_test, ensemble_preds, zero_division=0),
            "ensemble_roc_auc": roc_auc_score(y_test, ensemble_proba),
            "best_threshold": best_threshold,
        }

        # Per-model metrics
        for name, probs in [("xgb", prob_xgb), ("lgbm", prob_lgbm), ("rf", prob_rf), ("gb", prob_gb)]:
            preds = (probs >= 0.5).astype(int)
            ensemble_metrics[f"{name}_f1"] = f1_score(y_test, preds)
            ensemble_metrics[f"{name}_accuracy"] = accuracy_score(y_test, preds)
            ensemble_metrics[f"{name}_roc_auc"] = roc_auc_score(y_test, probs)

        # Log all metrics to MLflow
        mlflow.log_metrics(ensemble_metrics)

        train_duration = time.time() - train_start_time
        mlflow.log_metric("training_duration_seconds", train_duration)

        # ── Log confusion matrix as artifact ──
        cm = confusion_matrix(y_test, ensemble_preds)
        cm_report = classification_report(y_test, ensemble_preds, target_names=["Normal", "Threat"])
        report_path = os.path.join(OUTPUT_DIR, "classification_report.txt")
        with open(report_path, "w") as f:
            f.write(f"Confusion Matrix:\n{cm}\n\n")
            f.write(f"Classification Report:\n{cm_report}\n")
            f.write(f"\nBest Threshold: {best_threshold:.4f}\n")
            f.write(f"Training Duration: {train_duration:.1f}s\n")
        mlflow.log_artifact(report_path)

        # ── Save and log model artifacts ──
        artifacts = {
            "xgb_model": xgb_model,
            "lgbm_model": lgbm_model,
            "rf_model": rf_model,
            "gb_model": gb_model,
            "label_encoders": label_encoders,
            "feature_cols": feature_cols,
            "weights": weights,
            "best_threshold": best_threshold
        }

        artifacts_path = os.path.join(OUTPUT_DIR, "pipeline_artifacts_v2.joblib")
        joblib.dump(artifacts, artifacts_path, compress=3)

        # Log the joblib artifact to MLflow
        mlflow.log_artifact(artifacts_path)
        mlflow.log_artifact(profiles_path)
        mlflow.log_artifact(test_events_path)

        # Log the ensemble as an sklearn model to the MLflow Model Registry
        # Use XGBoost model as the "primary" logged model for the registry
        mlflow.xgboost.log_model(
            xgb_model,
            artifact_path="xgb_model",
            registered_model_name="HPE-XGBoost-ThreatDetector",
        )
        mlflow.sklearn.log_model(
            rf_model,
            artifact_path="rf_model",
            registered_model_name="HPE-RandomForest-ThreatDetector",
        )

        # Tag the run
        mlflow.set_tags({
            "project": "HPE-Enterprise-Threat-Detection",
            "pipeline_version": "v2",
            "ensemble_type": "weighted",
            "smote_applied": "true",
            "n_models": "4",
        })
        
        print(f"\n{'='*70}")
        print(f"  [OK] Artifacts saved to {artifacts_path}")
        print(f"  [OK] MLflow Run ID: {run_id}")
        print(f"  [OK] Training time: {train_duration:.1f}s")
        print(f"  [OK] Metrics logged: {len(ensemble_metrics)} metrics")
        print(f"{'='*70}")

if __name__ == "__main__":
    main()
