-- host_php_projects inventories PHP projects discovered on the
-- local filesystem. Each row is one detected project root; the
-- detector follows the Tier-A markers from the PHP-project
-- fingerprint catalogue (iter 1-6): unique CLI bin or config
-- file presence => single-shot identification.
--
-- Walk roots (Linux):
--   /var/www, /var/www/html, /srv/www, /srv/http, /opt,
--   /usr/share, /home/<user>/public_html, /home/<user>
--   (configurable via PHP_PROJECTS_DIR env var)
--
-- Read-only by intent. The collector reads marker files for
-- classification + small evidence excerpts; it never writes,
-- modifies, or executes any discovered project.
--
-- Catalogue coverage: 58 frameworks / runtimes from iter 1-6.
--
-- Risk shapes this table surfaces:
--   * Dev artifact leak (vendor/ or .git in a web-serving path)
--   * Credential exposure (.env present with DB_PASSWORD= etc.)
--   * Outdated framework (major version << current LTS)
--   * Install wizard left (post-install /install/, /setup/,
--     /installation/ directories that should be removed)
--   * World-writable project root (chmod 777 on /var/www/html)

CREATE TABLE IF NOT EXISTS host_php_projects (
    id                         INTEGER PRIMARY KEY AUTOINCREMENT,
    collected_at               TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    project_root               TEXT    NOT NULL,
    user_profile               TEXT    NOT NULL DEFAULT '',
    framework                  TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (framework IN (
            'unknown','laravel','lumen','symfony','slim','mezzio',
            'hyperf','spiral',
            'codeigniter3','codeigniter4','cakephp','yii2','phalcon','laminas',
            'wordpress','drupal','joomla','typo3','statamic','craft',
            'concrete','bolt','processwire','pico','grav',
            'octobercms','wintercms',
            'magento','magento2','woocommerce','sylius','shopware',
            'bagisto','prestashop','opencart',
            'phpbb','mybb','flarum',
            'mediawiki','dokuwiki','bookstack',
            'suitecrm','espocrm','vtiger',
            'dolibarr','glpi','mantis',
            'moodle',
            'roundcube','postfixadmin','ispconfig',
            'phpmyadmin','adminer',
            'filament','novapanel','backpack',
            'sculpin','jigsaw',
            'nextcloud','owncloud',
            'composer-only','other'
        )),
    framework_family           TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (framework_family IN (
            'unknown','micro-framework','full-framework','cms',
            'ecommerce','forum','wiki','lms','crm','erp',
            'helpdesk','mail-admin','hosting-panel','db-admin',
            'admin-panel','static-builder','file-share',
            'composer-only','other'
        )),
    detected_version           TEXT    NOT NULL DEFAULT '',
    evidence                   TEXT    NOT NULL DEFAULT '',
    confidence                 TEXT    NOT NULL DEFAULT 'unknown'
        CHECK (confidence IN ('a','b','c','d','unknown')),
    marker_path                TEXT    NOT NULL DEFAULT '',
    marker_hash                TEXT    NOT NULL DEFAULT '',
    project_size_bytes         INTEGER NOT NULL DEFAULT 0,
    file_count                 INTEGER NOT NULL DEFAULT 0,
    composer_json_present      INTEGER NOT NULL DEFAULT 0 CHECK (composer_json_present IN (0,1)),
    composer_lock_present      INTEGER NOT NULL DEFAULT 0 CHECK (composer_lock_present IN (0,1)),
    has_dotenv                 INTEGER NOT NULL DEFAULT 0 CHECK (has_dotenv IN (0,1)),
    has_dotenv_secret          INTEGER NOT NULL DEFAULT 0 CHECK (has_dotenv_secret IN (0,1)),
    is_git_repo                INTEGER NOT NULL DEFAULT 0 CHECK (is_git_repo IN (0,1)),
    has_vendor_dir             INTEGER NOT NULL DEFAULT 0 CHECK (has_vendor_dir IN (0,1)),
    has_node_modules_dir       INTEGER NOT NULL DEFAULT 0 CHECK (has_node_modules_dir IN (0,1)),
    has_install_wizard         INTEGER NOT NULL DEFAULT 0 CHECK (has_install_wizard IN (0,1)),
    is_world_writable_root     INTEGER NOT NULL DEFAULT 0 CHECK (is_world_writable_root IN (0,1)),
    is_world_readable_config   INTEGER NOT NULL DEFAULT 0 CHECK (is_world_readable_config IN (0,1)),
    is_under_web_root          INTEGER NOT NULL DEFAULT 0 CHECK (is_under_web_root IN (0,1)),
    is_recent                  INTEGER NOT NULL DEFAULT 0 CHECK (is_recent IN (0,1)),
    is_dev_artifact_leak_risk  INTEGER NOT NULL DEFAULT 0 CHECK (is_dev_artifact_leak_risk IN (0,1)),
    is_credential_exposure_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_credential_exposure_risk IN (0,1)),
    is_outdated_framework_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_outdated_framework_risk IN (0,1)),
    is_install_wizard_left_risk INTEGER NOT NULL DEFAULT 0 CHECK (is_install_wizard_left_risk IN (0,1)),
    is_world_writable_risk     INTEGER NOT NULL DEFAULT 0 CHECK (is_world_writable_risk IN (0,1)),
    UNIQUE (project_root)
);

CREATE INDEX IF NOT EXISTS idx_php_framework        ON host_php_projects(framework);
CREATE INDEX IF NOT EXISTS idx_php_family           ON host_php_projects(framework_family);
CREATE INDEX IF NOT EXISTS idx_php_confidence       ON host_php_projects(confidence);
CREATE INDEX IF NOT EXISTS idx_php_dev_leak         ON host_php_projects(project_root) WHERE is_dev_artifact_leak_risk = 1;
CREATE INDEX IF NOT EXISTS idx_php_cred_exposure    ON host_php_projects(project_root) WHERE is_credential_exposure_risk = 1;
CREATE INDEX IF NOT EXISTS idx_php_outdated         ON host_php_projects(framework, detected_version) WHERE is_outdated_framework_risk = 1;
CREATE INDEX IF NOT EXISTS idx_php_install_wizard   ON host_php_projects(project_root) WHERE is_install_wizard_left_risk = 1;
CREATE INDEX IF NOT EXISTS idx_php_writable         ON host_php_projects(project_root) WHERE is_world_writable_risk = 1;
CREATE INDEX IF NOT EXISTS idx_php_under_webroot    ON host_php_projects(project_root) WHERE is_under_web_root = 1;
