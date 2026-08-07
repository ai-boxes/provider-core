ALTER TABLE provider_models
ADD COLUMN pricing_source TEXT
CHECK (pricing_source IS NULL OR pricing_source IN ('catalog', 'manual'));

ALTER TABLE provider_models
ADD COLUMN pricing_json TEXT
CHECK (pricing_json IS NULL OR json_valid(pricing_json));

CREATE TRIGGER provider_models_pricing_insert_check
BEFORE INSERT ON provider_models
WHEN (NEW.pricing_source IS NULL) != (NEW.pricing_json IS NULL)
BEGIN
    SELECT RAISE(ABORT, 'provider model pricing source and json must be set together');
END;

CREATE TRIGGER provider_models_pricing_update_check
BEFORE UPDATE OF pricing_source, pricing_json ON provider_models
WHEN (NEW.pricing_source IS NULL) != (NEW.pricing_json IS NULL)
BEGIN
    SELECT RAISE(ABORT, 'provider model pricing source and json must be set together');
END;
