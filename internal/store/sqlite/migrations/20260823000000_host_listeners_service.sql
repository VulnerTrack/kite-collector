-- 20260823000000_host_listeners_service.sql: add the recognised service and
-- its version to host_listeners so the (now-wired) local listeners collector
-- can save what each open port is actually speaking, as named by the
-- fingerprintx -sV recogniser. Two nullable columns; nothing existing is
-- touched, and a listener with no recognised service simply leaves them NULL.
ALTER TABLE host_listeners ADD COLUMN service TEXT;
ALTER TABLE host_listeners ADD COLUMN service_version TEXT;
