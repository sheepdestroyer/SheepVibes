import logging

import sqlalchemy as sa
from alembic import op

logger = logging.getLogger(__name__)


def constraint_exists(table_name, constraint_name, type_="unique"):
    """
    Checks if a named constraint exists on a table.

    :param table_name: The name of the table.
    :param constraint_name: The name of the constraint to check.
    :param type_: The type of constraint (e.g., "unique", "foreignkey").
    :return: True if it exists, False otherwise.
    """
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if type_ == "unique":
        constraints = inspector.get_unique_constraints(table_name)
    elif type_ == "foreignkey":
        constraints = inspector.get_foreign_keys(table_name)
    elif type_ == "check":
        constraints = inspector.get_check_constraints(table_name)
    elif type_ == "primary":
        # Primary key is usually one per table, but return format is dict
        pk = inspector.get_pk_constraint(table_name)
        return pk.get("name") == constraint_name
    else:
        raise ValueError(f"Unsupported constraint type: {type_}")

    for c in constraints:
        if c.get("name") == constraint_name:
            return True
    return False


def safe_drop_constraint(table_name,
                         constraint_name,
                         type_="unique",
                         **kwargs):
    """
    Drops a constraint only if it exists.

    :param table_name: The name of the table.
    :param constraint_name: The name of the constraint to drop.
    :param type_: The type of constraint.
    :param kwargs: Additional arguments to pass to op.drop_constraint.
    """
    if constraint_name is None:
        logger.warning(
            f"Attempted to safe_drop_constraint with None name on table {table_name}. Skipping check, letting Alembic handle it (likely will fail if not handled by batch)."
        )
        # In batch mode, dropping None (unnamed) is sometimes valid if columns are provided,
        # but safe_drop is mostly for named constraints.
        # We'll just try it if the user insists, but really this helper is for named constraints.
        with op.batch_alter_table(table_name,
                                  schema=kwargs.get("schema")) as batch_op:
            batch_op.drop_constraint(constraint_name, type_=type_, **kwargs)
        return

    if constraint_exists(table_name, constraint_name, type_):
        with op.batch_alter_table(table_name,
                                  schema=kwargs.get("schema")) as batch_op:
            batch_op.drop_constraint(constraint_name, type_=type_, **kwargs)
        logger.info(f"Dropped constraint {constraint_name} from {table_name}")
    else:
        logger.info(
            f"Constraint {constraint_name} not found on {table_name}, skipping drop."
        )
