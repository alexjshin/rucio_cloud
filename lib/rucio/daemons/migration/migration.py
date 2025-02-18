import threading
import functools
import logging
import time
from typing import List, Tuple
from datetime import datetime
from lib.rucio.core.rse_expression_parser import parse_expression
from lib.rucio.core.rse_selector import RSESelector
from lib.rucio.daemons.migration.did import DID
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import SQLAlchemyError
from your_model_module import Migration  # Import the Migration model class
from cmo import identify_hyperplanes, compute_extremal_assignments
from intpoints.computeP import computePointsZeroB
from rucio.core.migration import get_migration_records
from rucio.common.logging import setup_logging
from rucio.daemons.common import run_daemon
from rucio.db.sqla.session import get_session

logging.getLogger("sqlalchemy").setLevel(logging.CRITICAL)
DAEMON_NAME = 'migration'
SLEEP_INTERVAL = 300  # 5 minutes in seconds
graceful_stop = threading.Event()
# pending_transfers = set()

def migration_injector(once=False, sleep_time=SLEEP_INTERVAL):
    """
    Main loop to check for asynchronous creation of replication rules
    """
    run_daemon(
        once=once,
        graceful_stop=graceful_stop,
        executable=DAEMON_NAME,
        partition_wait_time=1,
        sleep_time=sleep_time,
        run_once_fnc=functools.partial(
            run_once,
        )
    )

def run_once(heartbeat_handler, **_kwargs):
    """
    Main loop to check and process records from the Migration table.
    """
    
    worker_number, total_workers, logger = heartbeat_handler.live()
    while not graceful_stop.is_set():
        try:
            session = get_session()
            # Fetch new migration records
            records = get_migration_records(total_workers, worker_number, session=session)  # Ensure this function is defined and imported

            # Filter out non-cloud migrations
            
            non_cloud_records, cloud_records = separate_records_based_on_rse_expression(records)
            
            # Compute the non-cloud assignments
            optimal_assignment = {}
            compute_non_cloud_assignments(non_cloud_records, optimal_assignment, session)
            
            # Process records with CMO
            dids, feasible_rses = prepare_cloud_cmo_input(cloud_records, session)
            if dids and feasible_rses:
                hyperplanes = identify_hyperplanes(dids, feasible_rses, session)
                interior_points = computePointsZeroB(hyperplanes)  # Assuming this is defined in cmo.py
                compute_extremal_assignments(dids, feasible_rses, interior_points, optimal_assignment)

                # Process the optimal assignments as required
                process_optimal_assignments(optimal_assignment)
        except SQLAlchemyError as e:
            logging.error(f"Migration error occurred: {e}")

        logging.info(f"{DAEMON_NAME} daemon sleeping for {SLEEP_INTERVAL} seconds")
        time.sleep(SLEEP_INTERVAL)

def separate_records_based_on_rse_expression(records: List[Migration]):
    """
    Separate records into two lists based on the presence of 'cloud' in the rse_expression field.

    :param records: List of Migration records
    :return: A tuple of two lists - 
             1st list: Records without 'cloud' in rse_expression
             2nd list: Records with 'cloud' in rse_expression
    """
    records_with_cloud = []
    records_without_cloud = []

    for record in records:
        # Split the rse_expression by backslash and check for 'cloud'
        if any('cloud' in part for part in record.rse_expression.split('\\')):
            records_with_cloud.append(record)
        else:
            records_without_cloud.append(record)

    return records_without_cloud, records_with_cloud

def compute_non_cloud_assignments(non_cloud_records, optimal_assignment, session):
    
    for non_cloud_record in non_cloud_records:
        preferred_rses = parse_expression(non_cloud_record.rse_expression, filter_={'vo': non_cloud_record.account.vo}, session=session)
        rseselector = RSESelector(account=non_cloud_record.account,
                            rses=preferred_rses,
                            weight=non_cloud_record.weight,
                            copies=non_cloud_record.copies,
                            ignore_account_limit=non_cloud_record.ignore_account_limit,
                            session=session)
        target_rse = rseselector.select_rse(non_cloud_record.size, preferred_rses, non_cloud_record.copies)
        optimal_assignment[non_cloud_record] = target_rse


def prepare_cloud_cmo_input(records, session):
    dids = []
    feasible_rses = {}

    for record in records:
        # Create a DID object for each Migration record
        # Placeholder values for size and replicationRule as they are not part of the Migration schema
        did_obj = DID(did=record.name, size=0, replicationRule=record.rse_expression)
        dids.append(did_obj)

        # Determine feasible RSEs using the parse_expression function
        rses = parse_expression(record.rse_expression, filter_={'vo': record.account.vo}, session=session)
        feasible_rses[record.name] = rses

    return dids, feasible_rses

def process_optimal_assignments(assignments):
    """
    Sends the new assignments to the conveyor based on if their assignment has changed from their current RSE
    """
    
    pass

def stop(signum=None, frame=None):
    """
    Graceful exit.  
    """
    logging.info(f"{DAEMON_NAME} daemon stopping gracefully")
    graceful_stop.set()

def run(once=False, threads=1, sleep_time=SLEEP_INTERVAL):
    """
    Starts up the Judge-Injector threads.
    """
    setup_logging(process_name=DAEMON_NAME)

    if once:
        migration_injector(once)
    else:
        logging.info('Injector starting %s threads' % str(threads))
        threads = [threading.Thread(target=migration_injector, kwargs={'once': once,
                                                                  'sleep_time': sleep_time}) for i in range(0, threads)]
        [t.start() for t in threads]
        # Interruptible joins require a timeout.
        while threads[0].is_alive():
            [t.join(timeout=3.14) for t in threads]
