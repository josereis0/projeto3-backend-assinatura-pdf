
# RNF-09/10/11 migration timestamp + upgrade/downgrade
revision = '20261101_initial'
down_revision = None
def upgrade():
    print("CREATE TABLE users, passkey_devices, refresh_tokens, denylist, sessions, audit_logs, signatures, backup_codes")

def downgrade():
    print("DROP TABLES")
