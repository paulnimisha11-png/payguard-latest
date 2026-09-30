# PayGuard UPI scam model: model card

**Status: PROTOTYPE (v1).** Trained on synthetic prototype data (scripts/make_upi_dataset.py). The metrics below measure how well the model learned the scenarios in that dataset. They are **not** real-world accuracy and must not be presented as such. Replace the data with real labelled UPI payloads (see scripts/train_upi_model.py) before relying on the numbers.

## Model
- Selected: **gradient_boosting** ({'n_estimators': 300, 'max_depth': 3, 'learning_rate': 0.05, 'subsample': 0.8, 'min_samples_leaf': 5}), chosen on validation log-loss: {'random_forest': {'val_log_loss': 0.1525, 'val_roc_auc': 0.9717}, 'gradient_boosting': {'val_log_loss': 0.145, 'val_roc_auc': 0.9745}}
- Calibration: **isotonic** (chosen by 5-fold CV log-loss within the validation split: {'isotonic': 0.1441, 'sigmoid': 0.1451}), fitted on the validation split only. Output is limited to 1-99%: a model calibrated on about a thousand examples cannot justify certainty.
- **Base rate:** 40% of the training payloads are scams. Real-world scam rates are far lower, so on real traffic these probabilities overstate risk: read them as relative risk until the model is recalibrated on real data.
- Decision threshold: calibrated scam probability >= 0.5 → *Scam*.
- Runtime: trees + calibration exported to `app/ml/upi_model.json` and evaluated in pure Python (max difference from scikit-learn on the test set: 8.0e-16).

## Data
- Files: upi_synthetic_v1.csv; 6320 UPI payloads, 2551 scam / 3769 legitimate.
- Split (stratified, seed 7): train 3792, validation 1264, test 1264.

## Test-set results (synthetic data)

| | precision | recall | F1 | ROC-AUC | Brier | ECE (10 bins) |
|---|---|---|---|---|---|---|
| calibrated | 0.976 | 0.9569 | 0.9663 | 0.9814 | 0.0227 | 0.0128 |
| uncalibrated | 0.9741 | 0.9569 | 0.9654 | 0.9823 | 0.0241 | 0.0175 |

Confusion matrix (calibrated, test):

| | predicted legitimate | predicted scam |
|---|---|---|
| actually legitimate | 742 | 12 |
| actually scam | 22 | 488 |

Accuracy by scenario (test):

| scenario | label | n | accuracy |
|---|---|---|---|
| legit_biller | legit | 35 | 1.0 |
| legit_family_large | legit | 58 | 0.983 |
| legit_merchant_dynamic | legit | 91 | 1.0 |
| legit_merchant_static | legit | 172 | 0.983 |
| legit_p2p | legit | 251 | 0.988 |
| legit_rare_handle | legit | 25 | 1.0 |
| legit_small_shop | legit | 96 | 0.969 |
| legit_temple | legit | 24 | 0.958 |
| scam_autopay | scam | 33 | 0.939 |
| scam_collect | scam | 26 | 0.962 |
| scam_fake_merchant | scam | 37 | 1.0 |
| scam_impersonation | legit | 85 | 0.976 |
| scam_kyc_fee | scam | 42 | 0.952 |
| scam_link_in_note | scam | 24 | 1.0 |
| scam_olx_army | scam | 37 | 0.892 |
| scam_prize | scam | 42 | 1.0 |
| scam_quiet | scam | 42 | 0.81 |
| scam_refund_receive | scam | 101 | 0.99 |
| scam_tampered_qr | scam | 43 | 0.93 |

## Features

| feature | meaning | importance |
|---|---|---|
| `note_lure_words` | Payment note uses scam bait words | 0.314 |
| `authority_name_personal_account` | Official-sounding name on a personal (non-merchant) account | 0.2047 |
| `community_got_me` | People said this UPI ID took their money | 0.1401 |
| `note_everyday_words` | Payment note describes an everyday purpose (rent, fees, bill...) | 0.1293 |
| `payee_lure_words` | Payee name uses refund/prize/cashback words | 0.0532 |
| `format_problem_count` | Number of UPI format problems | 0.0338 |
| `amount_log10` | Size of the amount | 0.0248 |
| `merchant_code_present` | Registered merchant code (mc) present | 0.0245 |
| `uri_valid` | UPI link is correctly formatted | 0.0174 |
| `community_disputes` | People said this UPI ID is genuine | 0.0154 |
| `community_reports_log` | People have reported this UPI ID | 0.0112 |
| `payee_name_length` | Length of the payee name | 0.0068 |
| `vpa_local_digit_ratio` | Share of digits in the UPI ID | 0.0055 |
| `payee_authority_words` | Payee name claims to be a bank/police/government/support | 0.0044 |
| `vpa_length` | Length of the UPI ID | 0.0032 |
| `has_note` | Payment note is present | 0.0027 |
| `transaction_ref_present` | Transaction reference (tr) present | 0.0013 |
| `vpa_local_length` | Length of the part before @ | 0.0012 |
| `amount_ends_99` | Amount ends in 99 (e.g. 4,999) | 0.0012 |
| `recurring_params` | Contains recurring-payment parameters | 0.0009 |
| `vpa_long_digit_run` | UPI ID contains a long random-looking number | 0.0007 |
| `action_mandate` | It sets up AutoPay / repeated payments | 0.0006 |
| `action_collect` | It is a collect request (asks you to approve a payment) | 0.0005 |
| `lookalike_of_reported` | UPI ID looks like a reported scam ID | 0.0005 |
| `note_receive_words` | Payment note talks about receiving money | 0.0004 |
| `vpa_brand_or_authority` | UPI ID contains a bank/brand/authority word | 0.0003 |
| `payee_brand_words` | Payee name mentions a bank or payment brand | 0.0003 |
| `has_payee_name` | Payee name is present | 0.0002 |
| `note_has_link` | Payment note contains a link | 0.0002 |
| `note_has_phone` | Payment note contains a phone number | 0.0002 |
| `vpa_is_phone_number` | UPI ID is a mobile number | 0.0001 |
| `vpa_handle_known` | UPI handle (@bank) is a known bank/app | 0.0001 |
| `vpa_merchant_hint` | UPI ID looks like a merchant account | 0.0001 |
| `amount_round_thousand` | Amount is a round thousand | 0.0001 |
| `signed_qr` | QR is digitally signed | 0.0001 |
| `has_amount` | Amount is pre-filled | 0.0 |

## Known limitations
- Synthetic scenarios encode PayGuard's own understanding of scams; the model can only be as good as that picture.
- 'Quiet' scams (an ordinary-looking personal UPI ID) are only catchable through community reports.
- The probability is an estimate for payloads like the training data; unusual real-world QRs can be misjudged.
- PayGuard's safety guard still raises malformed links and critical rule findings to at least 'suspicious'.
