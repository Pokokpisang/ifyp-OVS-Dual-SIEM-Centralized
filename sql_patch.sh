#!/bin/bash
docker exec agent_db_1 psql -U user -d siemdb -c "ALTER TABLE logs ADD COLUMN IF NOT EXISTS local_flag BOOLEAN DEFAULT FALSE;"
docker exec agent_db_1 psql -U user -d siemdb -c "ALTER TABLE logs ADD COLUMN IF NOT EXISTS agent_rule_id INTEGER;"
docker exec agent_db_1 psql -U user -d siemdb -c "ALTER TABLE logs ADD COLUMN IF NOT EXISTS local_rule_version INTEGER;"
docker exec agent_db_1 psql -U user -d siemdb -c "ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS rule_type VARCHAR DEFAULT 'server';"
