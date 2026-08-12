ALTER TABLE provider_models
    ADD COLUMN input_modalities_json TEXT CHECK (
        input_modalities_json IS NULL
        OR CASE
            WHEN json_valid(input_modalities_json) THEN
                json_type(input_modalities_json) = 'array'
                AND json_array_length(input_modalities_json) BETWEEN 1 AND 5
                AND json_type(input_modalities_json, '$[0]') = 'text'
                AND json_extract(input_modalities_json, '$[0]')
                    IN ('text', 'image', 'pdf', 'audio', 'video')
                AND (
                    json_array_length(input_modalities_json) < 2
                    OR (
                        json_type(input_modalities_json, '$[1]') = 'text'
                        AND json_extract(input_modalities_json, '$[1]')
                            IN ('text', 'image', 'pdf', 'audio', 'video')
                        AND json_extract(input_modalities_json, '$[1]')
                            != json_extract(input_modalities_json, '$[0]')
                    )
                )
                AND (
                    json_array_length(input_modalities_json) < 3
                    OR (
                        json_type(input_modalities_json, '$[2]') = 'text'
                        AND json_extract(input_modalities_json, '$[2]')
                            IN ('text', 'image', 'pdf', 'audio', 'video')
                        AND json_extract(input_modalities_json, '$[2]')
                            NOT IN (
                                json_extract(input_modalities_json, '$[0]'),
                                json_extract(input_modalities_json, '$[1]')
                            )
                    )
                )
                AND (
                    json_array_length(input_modalities_json) < 4
                    OR (
                        json_type(input_modalities_json, '$[3]') = 'text'
                        AND json_extract(input_modalities_json, '$[3]')
                            IN ('text', 'image', 'pdf', 'audio', 'video')
                        AND json_extract(input_modalities_json, '$[3]')
                            NOT IN (
                                json_extract(input_modalities_json, '$[0]'),
                                json_extract(input_modalities_json, '$[1]'),
                                json_extract(input_modalities_json, '$[2]')
                            )
                    )
                )
                AND (
                    json_array_length(input_modalities_json) < 5
                    OR (
                        json_type(input_modalities_json, '$[4]') = 'text'
                        AND json_extract(input_modalities_json, '$[4]')
                            IN ('text', 'image', 'pdf', 'audio', 'video')
                        AND json_extract(input_modalities_json, '$[4]')
                            NOT IN (
                                json_extract(input_modalities_json, '$[0]'),
                                json_extract(input_modalities_json, '$[1]'),
                                json_extract(input_modalities_json, '$[2]'),
                                json_extract(input_modalities_json, '$[3]')
                            )
                    )
                )
            ELSE 0
        END
    );

ALTER TABLE provider_models
    ADD COLUMN input_modalities_source TEXT NOT NULL DEFAULT 'discovery'
        CHECK (input_modalities_source IN ('discovery', 'manual'));
