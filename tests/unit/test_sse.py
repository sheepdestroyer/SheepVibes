import queue
import unittest
from unittest.mock import MagicMock, patch

from backend.sse import MessageAnnouncer


class TestMessageAnnouncer(unittest.TestCase):
    def setUp(self):
        self.announcer = MessageAnnouncer()

    def test_announce_broadcasts_to_all_listeners(self):
        """Test that announce puts the message in all listener queues."""
        # Create mock queues
        q1 = MagicMock()
        q2 = MagicMock()

        # Manually add them to listeners (simulating connected clients)
        self.announcer.listeners.append(q1)
        self.announcer.listeners.append(q2)

        message = "test message"
        self.announcer.announce(message)

        # Verify put_nowait was called on both
        q1.put_nowait.assert_called_once_with(message)
        q2.put_nowait.assert_called_once_with(message)

    @patch("backend.sse.logger")
    def test_announce_handles_full_queue(self, mock_logger):
        """Test that announce handles a full queue gracefully."""
        # Create a queue that raises queue.Full
        full_queue = MagicMock()
        full_queue.put_nowait.side_effect = queue.Full

        # Create a normal queue
        normal_queue = MagicMock()

        self.announcer.listeners.append(full_queue)
        self.announcer.listeners.append(normal_queue)

        message = "test message"
        self.announcer.announce(message)

        # Verify full queue raised exception (side_effect) but execution continued
        full_queue.put_nowait.assert_called_once_with(message)

        # Verify normal queue still received the message
        normal_queue.put_nowait.assert_called_once_with(message)

        # Verify warning was logged
        mock_logger.warning.assert_called_with(
            "A client's SSE message queue was full. Dropping message."
        )

    @patch("backend.sse.queue.Queue")
    def test_listen_yields_messages(self, mock_queue_cls):
        """Test that listen yields messages from the queue."""
        # Create a mock queue instance
        mock_queue = MagicMock()
        mock_queue_cls.return_value = mock_queue

        # Set up get() to return messages
        mock_queue.get.side_effect = ["message 1", "message 2", "message 3"]

        # Use the generator
        gen = self.announcer.listen()

        # 1st message
        msg1 = next(gen)
        self.assertEqual(msg1, "message 1")
        # Verify added to listeners while active
        self.assertIn(mock_queue, self.announcer.listeners)

        # 2nd message
        msg2 = next(gen)
        self.assertEqual(msg2, "message 2")
        self.assertIn(mock_queue, self.announcer.listeners)

        # Stop generator
        gen.close()

        # Verify queue was removed from listeners
        self.assertNotIn(mock_queue, self.announcer.listeners)

        # Verify get was called with timeout=1.0
        mock_queue.get.assert_called_with(timeout=1.0)

    @patch("backend.sse.queue.Queue")
    def test_listen_sends_heartbeat(self, mock_queue_cls):
        """Test that listen sends a heartbeat when queue is empty."""
        mock_queue = MagicMock()
        mock_queue_cls.return_value = mock_queue

        # Raise queue.Empty once
        mock_queue.get.side_effect = [queue.Empty, "msg"]

        gen = self.announcer.listen()

        # First yield should be heartbeat
        msg = next(gen)
        self.assertEqual(msg, ": heartbeat\n\n")

        gen.close()

    @patch("backend.sse.queue.Queue")
    def test_listen_cleanup_on_client_disconnect(self, mock_queue_cls):
        """Test that listen cleans up resources when client disconnects (GeneratorExit)."""
        mock_queue = MagicMock()
        mock_queue_cls.return_value = mock_queue

        mock_queue.get.return_value = "msg"

        gen = self.announcer.listen()
        next(gen)

        self.assertIn(mock_queue, self.announcer.listeners)

        # Simulate client disconnect by closing the generator
        gen.close()

        # Verify queue is removed from listeners
        self.assertNotIn(mock_queue, self.announcer.listeners)

    @patch("backend.sse.queue.Queue")
    def test_listen_cleanup_error_handling(self, mock_queue_cls):
        """Test cleanup when removing the queue raises ValueError (already removed)."""
        mock_queue = MagicMock()
        mock_queue_cls.return_value = mock_queue

        # Replace listeners list with a Mock object that has append/remove methods
        self.announcer.listeners = MagicMock()
        # Ensure remove raises ValueError
        self.announcer.listeners.remove.side_effect = ValueError

        mock_queue.get.return_value = "msg"

        gen = self.announcer.listen()
        next(gen)

        # This should not raise an exception
        gen.close()

        # Verify remove was called
        self.announcer.listeners.remove.assert_called_with(mock_queue)

    @patch("backend.sse.queue.Queue")
    def test_listen_concurrency_lock(self, mock_queue_cls):
        """Test that adding/removing listeners uses the lock."""
        mock_queue = MagicMock()
        mock_queue_cls.return_value = mock_queue

        # Mock the lock context manager
        self.announcer.lock = MagicMock()
        self.announcer.lock.__enter__ = MagicMock()
        self.announcer.lock.__exit__ = MagicMock()

        gen = self.announcer.listen()
        next(gen)  # Trigger entering the loop

        # Verify lock was acquired for appending
        self.announcer.lock.__enter__.assert_called()

        gen.close()

        # Verify lock was acquired for removing (called at least twice total)
        self.assertGreaterEqual(self.announcer.lock.__enter__.call_count, 2)


if __name__ == "__main__":
    unittest.main()
