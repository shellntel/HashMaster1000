"""
Chunked Analysis Infrastructure for AAIA

Provides reusable chunking, progress tracking, time estimation,
and result aggregation for processing large datasets without sampling loss.

Usage:
    manager = ChunkManager(config=ChunkConfig(chunk_size=100))

    for progress, chunk_result in manager.process_chunks(items, process_fn):
        yield progress  # Stream progress updates

    final_results = manager.get_aggregated_results(dedupe_key_fn)
"""
from dataclasses import dataclass, field
from typing import TypeVar, Generic, Iterator, Callable, Any
import time


@dataclass
class ChunkConfig:
    """Configuration for chunk processing."""
    chunk_size: int = 100  # Items per chunk (configurable 25-500)
    max_concurrent: int = 1  # 1 = sequential, >1 = parallel (future)
    timeout_per_chunk: float = 300.0  # 5 minutes default
    enable_deduplication: bool = True

    def validate(self) -> None:
        """Validate configuration values."""
        if self.chunk_size < 1:
            raise ValueError("chunk_size must be at least 1")
        if self.chunk_size > 1000:
            raise ValueError("chunk_size should not exceed 1000")
        if self.max_concurrent < 1:
            raise ValueError("max_concurrent must be at least 1")


@dataclass
class ChunkProgress:
    """Progress tracking for a chunked operation."""
    total_items: int = 0
    total_chunks: int = 0
    completed_chunks: int = 0
    current_chunk: int = 0
    items_processed: int = 0
    start_time: float = 0.0
    chunk_times: list[float] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def percent_complete(self) -> float:
        """Percentage of chunks completed."""
        if self.total_chunks == 0:
            return 0.0
        return (self.completed_chunks / self.total_chunks) * 100

    @property
    def elapsed_seconds(self) -> float:
        """Total elapsed time since start."""
        if self.start_time == 0:
            return 0.0
        return time.time() - self.start_time

    @property
    def avg_chunk_time(self) -> float:
        """Average time per chunk."""
        if not self.chunk_times:
            return 0.0
        return sum(self.chunk_times) / len(self.chunk_times)

    @property
    def estimated_remaining_seconds(self) -> float:
        """Estimated time remaining based on average chunk time."""
        remaining_chunks = self.total_chunks - self.completed_chunks
        return remaining_chunks * self.avg_chunk_time

    @property
    def is_complete(self) -> bool:
        """Whether all chunks have been processed."""
        return self.completed_chunks >= self.total_chunks

    def to_dict(self) -> dict[str, Any]:
        """Convert to JSON-serializable dict."""
        return {
            "total_items": self.total_items,
            "total_chunks": self.total_chunks,
            "completed_chunks": self.completed_chunks,
            "current_chunk": self.current_chunk,
            "items_processed": self.items_processed,
            "percent_complete": round(self.percent_complete, 1),
            "elapsed_seconds": round(self.elapsed_seconds, 1),
            "elapsed_formatted": format_time(self.elapsed_seconds),
            "estimated_remaining_seconds": round(self.estimated_remaining_seconds, 1),
            "estimated_remaining_formatted": format_time(self.estimated_remaining_seconds),
            "avg_chunk_time": round(self.avg_chunk_time, 2),
            "is_complete": self.is_complete,
            "error_count": len(self.errors)
        }


# Type variables for generic typing
T = TypeVar('T')  # Item type
R = TypeVar('R')  # Result type


@dataclass
class ChunkResult(Generic[R]):
    """Result from processing a single chunk."""
    chunk_index: int
    items_in_chunk: int
    items_processed: int
    results: list[R]
    processing_time: float
    error: str | None = None

    @property
    def success(self) -> bool:
        """Whether the chunk was processed successfully."""
        return self.error is None

    def to_dict(self) -> dict[str, Any]:
        """Convert to JSON-serializable dict (without results)."""
        return {
            "chunk_index": self.chunk_index,
            "items_in_chunk": self.items_in_chunk,
            "items_processed": self.items_processed,
            "result_count": len(self.results),
            "processing_time": round(self.processing_time, 2),
            "success": self.success,
            "error": self.error
        }


@dataclass
class AggregatedResults(Generic[R]):
    """Aggregated results from all chunks."""
    total_items: int
    total_chunks: int
    all_results: list[R]
    unique_results: list[R]  # After deduplication
    duplicates_removed: int
    total_time: float
    chunk_results: list[ChunkResult[R]]
    progress: ChunkProgress

    def to_dict(self) -> dict[str, Any]:
        """Convert to JSON-serializable dict (without full results)."""
        return {
            "total_items": self.total_items,
            "total_chunks": self.total_chunks,
            "total_results": len(self.all_results),
            "unique_results": len(self.unique_results),
            "duplicates_removed": self.duplicates_removed,
            "total_time": round(self.total_time, 2),
            "total_time_formatted": format_time(self.total_time),
            "successful_chunks": sum(1 for cr in self.chunk_results if cr.success),
            "failed_chunks": sum(1 for cr in self.chunk_results if not cr.success)
        }


@dataclass
class TimeEstimate:
    """Time estimation for processing a dataset."""
    total_items: int
    num_chunks: int
    chunk_size: int
    estimated_seconds: float
    warning_level: str  # "low", "medium", "high"

    @property
    def estimated_minutes(self) -> float:
        return self.estimated_seconds / 60

    @property
    def formatted(self) -> str:
        return format_time(self.estimated_seconds)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_items": self.total_items,
            "num_chunks": self.num_chunks,
            "chunk_size": self.chunk_size,
            "estimated_seconds": round(self.estimated_seconds, 1),
            "estimated_minutes": round(self.estimated_minutes, 1),
            "formatted": self.formatted,
            "warning_level": self.warning_level
        }


def format_time(seconds: float) -> str:
    """Format seconds as human-readable time string."""
    if seconds < 0:
        return "0s"
    elif seconds < 60:
        return f"{int(seconds)}s"
    elif seconds < 3600:
        mins = int(seconds // 60)
        secs = int(seconds % 60)
        return f"{mins}m {secs}s"
    else:
        hours = int(seconds // 3600)
        mins = int((seconds % 3600) // 60)
        return f"{hours}h {mins}m"


def get_warning_level(total_items: int, estimated_seconds: float) -> str:
    """
    Determine warning level for a dataset.

    Returns:
        "low" - Small dataset, quick processing
        "medium" - Moderate dataset, may take a while
        "high" - Large dataset, significant time required
    """
    if total_items > 50000 or estimated_seconds > 1800:  # >50K items or >30 min
        return "high"
    elif total_items > 10000 or estimated_seconds > 600:  # >10K items or >10 min
        return "medium"
    return "low"


class ChunkManager(Generic[T, R]):
    """
    Manages chunked processing of large datasets.

    Provides:
    - Configurable chunk sizes
    - Progress tracking with time estimates
    - Result aggregation with deduplication
    - Error handling per chunk

    Example:
        config = ChunkConfig(chunk_size=100)
        manager = ChunkManager(config)

        # Get time estimate before starting
        estimate = manager.estimate_time(len(items))
        if estimate.warning_level == "high":
            # Show warning to user

        # Process with streaming progress
        for progress, chunk_result in manager.process_chunks(items, my_process_fn):
            if chunk_result:
                print(f"Chunk {chunk_result.chunk_index}: {len(chunk_result.results)} results")
            print(f"Progress: {progress.percent_complete}%")

        # Get aggregated results
        results = manager.get_aggregated_results(dedupe_key_fn=lambda r: r.id)
    """

    # Default time per chunk for estimation (seconds)
    DEFAULT_CHUNK_TIME = 30.0

    def __init__(self, config: ChunkConfig | None = None):
        self.config = config or ChunkConfig()
        self.config.validate()
        self.progress = ChunkProgress()
        self.chunk_results: list[ChunkResult[R]] = []
        self._sample_chunk_time: float | None = None

    def estimate_time(
        self,
        total_items: int,
        sample_time: float | None = None,
        categories: int = 1
    ) -> TimeEstimate:
        """
        Estimate processing time for a dataset.

        Args:
            total_items: Number of items to process
            sample_time: Optional measured time from a sample run (seconds per chunk)
            categories: Number of categories to analyze (multiplier for total time)

        Returns:
            TimeEstimate with time and warning level
        """
        num_chunks = (total_items + self.config.chunk_size - 1) // self.config.chunk_size

        # Use sample time if provided, or stored sample, or default
        time_per_chunk = sample_time or self._sample_chunk_time or self.DEFAULT_CHUNK_TIME

        total_seconds = num_chunks * time_per_chunk * categories

        return TimeEstimate(
            total_items=total_items,
            num_chunks=num_chunks * categories,
            chunk_size=self.config.chunk_size,
            estimated_seconds=total_seconds,
            warning_level=get_warning_level(total_items, total_seconds)
        )

    def create_chunks(self, items: list[T]) -> Iterator[tuple[int, list[T]]]:
        """
        Split items into chunks.

        Args:
            items: List of items to chunk

        Yields:
            Tuple of (chunk_index, chunk_items)
        """
        for i in range(0, len(items), self.config.chunk_size):
            chunk = items[i:i + self.config.chunk_size]
            yield i // self.config.chunk_size, chunk

    def process_chunks(
        self,
        items: list[T],
        process_fn: Callable[[list[T], int], list[R]]
    ) -> Iterator[tuple[ChunkProgress, ChunkResult[R] | None]]:
        """
        Process items in chunks, yielding progress updates.

        Args:
            items: List of items to process
            process_fn: Function that takes (chunk_items, chunk_index) and returns results

        Yields:
            Tuple of (progress, chunk_result or None)
            - First yield per chunk has chunk_result=None (before processing)
            - Second yield has the actual result
        """
        total_chunks = (len(items) + self.config.chunk_size - 1) // self.config.chunk_size

        self.progress = ChunkProgress(
            total_items=len(items),
            total_chunks=total_chunks,
            start_time=time.time()
        )
        self.chunk_results = []

        for chunk_index, chunk in self.create_chunks(items):
            self.progress.current_chunk = chunk_index + 1

            # Yield progress before processing (for UI updates)
            yield self.progress, None

            # Process the chunk
            chunk_start = time.time()
            try:
                results = process_fn(chunk, chunk_index)
                chunk_time = time.time() - chunk_start

                chunk_result = ChunkResult(
                    chunk_index=chunk_index,
                    items_in_chunk=len(chunk),
                    items_processed=len(chunk),
                    results=results,
                    processing_time=chunk_time
                )

                # Store first chunk time as sample for estimates
                if self._sample_chunk_time is None:
                    self._sample_chunk_time = chunk_time

            except Exception as e:
                chunk_time = time.time() - chunk_start
                error_msg = str(e)

                chunk_result = ChunkResult(
                    chunk_index=chunk_index,
                    items_in_chunk=len(chunk),
                    items_processed=0,
                    results=[],
                    processing_time=chunk_time,
                    error=error_msg
                )
                self.progress.errors.append(f"Chunk {chunk_index}: {error_msg}")

            self.chunk_results.append(chunk_result)
            self.progress.chunk_times.append(chunk_time)
            self.progress.completed_chunks += 1
            self.progress.items_processed += chunk_result.items_processed

            # Yield progress with result
            yield self.progress, chunk_result

    def get_aggregated_results(
        self,
        dedupe_key_fn: Callable[[R], str] | None = None
    ) -> AggregatedResults[R]:
        """
        Get aggregated results from all chunks with optional deduplication.

        Args:
            dedupe_key_fn: Function to extract deduplication key from a result.
                          If None, no deduplication is performed.

        Returns:
            AggregatedResults with all and unique results
        """
        # Collect all results from successful chunks
        all_results: list[R] = []
        for cr in self.chunk_results:
            if cr.success:
                all_results.extend(cr.results)

        # Deduplicate if requested
        if dedupe_key_fn and self.config.enable_deduplication:
            seen: set[str] = set()
            unique_results: list[R] = []
            for r in all_results:
                key = dedupe_key_fn(r)
                if key not in seen:
                    seen.add(key)
                    unique_results.append(r)
            duplicates = len(all_results) - len(unique_results)
        else:
            unique_results = all_results
            duplicates = 0

        return AggregatedResults(
            total_items=self.progress.total_items,
            total_chunks=self.progress.total_chunks,
            all_results=all_results,
            unique_results=unique_results,
            duplicates_removed=duplicates,
            total_time=self.progress.elapsed_seconds,
            chunk_results=self.chunk_results,
            progress=self.progress
        )

    def reset(self) -> None:
        """Reset the manager for a new processing run."""
        self.progress = ChunkProgress()
        self.chunk_results = []
        self._sample_chunk_time = None
