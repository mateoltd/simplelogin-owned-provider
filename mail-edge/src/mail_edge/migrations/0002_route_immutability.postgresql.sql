CREATE FUNCTION mail_edge_reject_route_generation_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.domain <> OLD.domain
       OR NEW.direction <> OLD.direction
       OR NEW.generation <> OLD.generation
       OR NEW.provider <> OLD.provider
       OR NEW.provider_config <> OLD.provider_config
       OR NEW.qualified_policy_version <> OLD.qualified_policy_version THEN
        RAISE EXCEPTION 'route generation is immutable';
    END IF;
    RETURN NEW;
END;
$$;
-- statement-break
CREATE TRIGGER route_generation_immutable
BEFORE UPDATE ON route_generations
FOR EACH ROW EXECUTE FUNCTION mail_edge_reject_route_generation_mutation();

