import logging

import sqlalchemy as sa
from alembic import op

logger = logging.getLogger(__name__)


def constraint_exists(table_name,
                      constraint_name,
                      type_="unique",
                      schema=None):
    """
    Checks if a named constraint exists on a table.

    :param table_name: The name of the table.
    :param constraint_name: The name of the constraint to check.
    :param type_: The type of constraint (e.g., "unique", "foreignkey").
    :param schema: The schema name (optional).
    :return: True if it exists, False otherwise.
    """
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if type_ == "primary":
        # Primary key is usually one per table, but return format is dict
        pk = inspector.get_pk_constraint(table_name, schema=schema)
        return pk and pk.get("name") == constraint_name

    inspector_methods = {
        "unique": inspector.get_unique_constraints,
        "foreignkey": inspector.get_foreign_keys,
        "check": inspector.get_check_constraints,
    }

    getter = inspector_methods.get(type_)
    if not getter:
        raise ValueError(f"Unsupported constraint type: {type_}")

    constraints = getter(table_name, schema=schema)
    return any(c.get("name") == constraint_name for c in constraints)


def safe_drop_constraint(table_name,
                         constraint_name,
                         type_="unique",
                         batch_op=None,
                         **kwargs):
    """
    Drops a constraint only if it exists.

    :param table_name: The name of the table.
    :param constraint_name: The name of the constraint to drop. If None, the operation is a no-op.
    :param type_: The type of constraint (e.g., "unique", "foreignkey", "check", "primary").
    :param batch_op: Optional existing batch operation context.
    :param kwargs: Additional arguments to pass to op.drop_constraint.
    """
    schema = kwargs.pop("schema", None)

    if constraint_name is None:
        logger.warning(
            "Attempted to safe_drop_constraint with None name on table %s. This is a no-op; callers must provide an explicit constraint name.",
            table_name,
        )
        return

    if not constraint_exists(table_name, constraint_name, type_,
                             schema=schema):
        logger.info("Constraint %s not found on %s, skipping drop.",
                    constraint_name, table_name)
        return

    # If we reach here, we should attempt to drop the constraint.
    if batch_op:
        batch_op.drop_constraint(constraint_name, type_=type_, **kwargs)
    else:
        with op.batch_alter_table(table_name, schema=schema) as batch_op_new:
            batch_op_new.drop_constraint(constraint_name,
                                         type_=type_,
                                         **kwargs)

    logger.info("Dropped constraint %s from %s", constraint_name, table_name)
