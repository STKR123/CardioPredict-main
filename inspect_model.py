import joblib

# Option 1: Full absolute path
#model = joblib.load(r"C:\Users\ADMIN\Downloads\CardioPredict-main\CardioPredict-main\model.pkl")

# Option 2: Relative path (works if inspect_model.py is in same folder as model.pkl)
model = joblib.load("model.pkl")

print("✅ Model loaded successfully!\n")
print("Model type:", type(model))
print("\nModel parameters:\n", model.get_params())

if hasattr(model, "feature_names_in_"):
    print("\nFeatures used in training:\n", model.feature_names_in_)

if hasattr(model, "estimators_"):
    print("\nNumber of trees in forest:", len(model.estimators_))

if hasattr(model, "feature_importances_"):
    print("\nFeature importances:\n", model.feature_importances_)
