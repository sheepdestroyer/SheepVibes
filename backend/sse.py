import logging
import queue
from threading import Lock

logger = logging.getLogger(__name__)


class MessageAnnouncer:
    """A simple message announcer that uses server-sent events.

    This class manages a list of listener queues. When a message is announced,
    it is put into each queue. The listen method yields messages from a queue,
    allowing for real-time communication with clients.
    """

    def __init__(self):
        """Initializes the MessageAnnouncer."""
        self.listeners = []
        self.lock = Lock()

    def listen(self):
        """Listens for messages and yields them to the client.

        This is a generator function that maintains a connection with the client.
        It adds a new queue to the listeners and then enters an infinite loop,
        yielding messages as they become available.

        Yields:
            str: A message from the queue, formatted for SSE.
        """
        q = queue.Queue(maxsize=5)
        with self.lock:
            self.listeners.append(q)

        try:
            while True:
                try:
                    # Using a timeout on get() makes the loop non-blocking from the
                    # perspective of the wsgi server, allowing it to handle client
                    # disconnects gracefully.
                    msg = q.get(timeout=1.0)
                    yield msg
                except queue.Empty:
                    # Send a heartbeat comment to keep the connection alive
                    # and, crucially, to provide a yield point for GeneratorExit
                    # to be raised when the client disconnects.
                    yield ": heartbeat\n\n"
        finally:
            # This is triggered when the client disconnects or an error occurs
            with self.lock:
                try:
                    self.listeners.remove(q)
                except ValueError:
                    # Already removed
                    pass

    def announce(self, msg):
        """Announces a message to all listening clients.

        Args:
            msg (str): The message to announce.
        """
        # Use a copy of the list to avoid issues if a client disconnects
        # during iteration.
        with self.lock:
            current_listeners = list(self.listeners)

        for q in current_listeners:
            try:
                q.put_nowait(msg)
            except queue.Full:
                # Client's queue is full, drop the message.
                logger.warning(
                    "A client's SSE message queue was full. Dropping message."
                )
                pass


announcer = MessageAnnouncer()
