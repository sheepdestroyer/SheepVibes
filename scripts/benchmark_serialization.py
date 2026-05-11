import sys
import os
import time
import datetime
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, ForeignKey, Index, StaticPool
from sqlalchemy.orm import declarative_base, sessionmaker, relationship

Base = declarative_base()

class FeedItem(Base):
    __tablename__ = "feed_items"
    id = Column(Integer, primary_key=True)
    feed_id = Column(Integer, index=True)
    title = Column(String, nullable=False)
    link = Column(String, nullable=False)
    published_time = Column(DateTime, nullable=True, index=True)
    fetched_time = Column(DateTime, nullable=False, default=datetime.datetime.utcnow)
    is_read = Column(Boolean, nullable=False, default=False, index=True)
    guid = Column(String, nullable=True)

    @staticmethod
    def to_iso_z_string(dt_val):
        if dt_val is None:
            return None
        return dt_val.strftime("%Y-%m-%dT%H:%M:%SZ")

    def to_dict(self):
        return {
            "id": self.id,
            "feed_id": self.feed_id,
            "title": self.title,
            "link": self.link,
            "published_time": FeedItem.to_iso_z_string(self.published_time),
            "fetched_time": FeedItem.to_iso_z_string(self.fetched_time),
            "is_read": self.is_read,
            "guid": self.guid,
        }

    def to_dict_optimized(self):
        return {
            "id": self.id,
            "feed_id": self.feed_id,
            "title": self.title,
            "link": self.link,
            "published_time": self.published_time.strftime("%Y-%m-%dT%H:%M:%SZ") if self.published_time else None,
            "fetched_time": self.fetched_time.strftime("%Y-%m-%dT%H:%M:%SZ") if self.fetched_time else None,
            "is_read": self.is_read,
            "guid": self.guid,
        }

def benchmark():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    # Create 1000 items
    items = [
        FeedItem(
            feed_id=1,
            title=f"Title {i}",
            link=f"http://link{i}.com",
            published_time=datetime.datetime.utcnow(),
            guid=f"guid{i}"
        ) for i in range(1000)
    ]
    session.add_all(items)
    session.commit()

    # Fetch items
    objs = session.query(FeedItem).all()

    # Benchmark original to_dict
    start = time.perf_counter()
    for _ in range(10):
        [obj.to_dict() for obj in objs]
    original_time = (time.perf_counter() - start) / 10
    print(f"Original to_dict: {original_time:.4f}s per 1000 items")

    # Benchmark optimized to_dict
    start = time.perf_counter()
    for _ in range(10):
        [obj.to_dict_optimized() for obj in objs]
    optimized_time = (time.perf_counter() - start) / 10
    print(f"Optimized to_dict: {optimized_time:.4f}s per 1000 items")
    
    improvement = (original_time - optimized_time) / original_time * 100
    print(f"Improvement: {improvement:.2f}%")

if __name__ == "__main__":
    benchmark()
