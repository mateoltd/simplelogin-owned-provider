CREATE TRIGGER route_generation_immutable
BEFORE UPDATE OF domain, direction, generation, provider, provider_config,
    qualified_policy_version ON route_generations
BEGIN
    SELECT RAISE(ABORT, 'route generation is immutable');
END;

