import os
import json
import uuid
import math
from loguru import logger
from typing import List, Dict, Any, Optional
from datetime import datetime

import chromadb
from chromadb.config import Settings
from chromadb.utils import embedding_functions

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Get configuration from environment
_CHROMA_PERSIST_DIR = os.getenv("CHROMA_PERSIST_DIR", "./chroma_db")
_COLLECTION_NAME = os.getenv("CHROMA_COLLECTION_NAME", "security_logs")

logger.info(f"Initializing ChromaDB with persist_dir: {_CHROMA_PERSIST_DIR}, collection: {_COLLECTION_NAME}")

class ChromaDBLogStore:
    """ChromaDB-based log storage and vector search."""
    
    def __init__(self, persist_dir: str = None, collection_name: str = None):
        self.persist_dir = persist_dir or _CHROMA_PERSIST_DIR
        self.collection_name = collection_name or _COLLECTION_NAME
        self.client = None
        self.collection = None
        self._initialize_db()
    
    def _initialize_db(self):
        """Initialize ChromaDB client and collection."""
        try:
            # Create persistent ChromaDB client
            self.client = chromadb.PersistentClient(path=self.persist_dir)
            
            # Get or create collection with default embedding function
            self.collection = self.client.get_or_create_collection(
                name=self.collection_name,
                metadata={"hnsw:space": "cosine"}
            )
            
            logger.info(f"ChromaDB initialized with {self.collection.count()} documents")
            
        except Exception as e:
            logger.error(f"Failed to initialize ChromaDB: {e}")
            self.client = None
            self.collection = None
    
    def _generate_embedding(self, text: str) -> List[float]:
        """Generate embedding using ChromaDB's default embedding function."""
        if not text or not text.strip():
            raise ValueError("Input text is empty.")
        
        logger.info(f"Generating embedding for text: {text[:100]}...")
        
        try:
            # Use ChromaDB's default embedding function (sentence-transformers/all-MiniLM-L6-v2)
            embedding_function = embedding_functions.DefaultEmbeddingFunction()
            embedding = embedding_function([text])
            
            if not embedding or not embedding[0]:
                raise RuntimeError("Failed to generate embedding")
            
            logger.info(f"Generated embedding with {len(embedding[0])} dimensions")
            return embedding[0]
            
        except Exception as e:
            logger.error(f"Embedding generation failed: {e}")
            raise RuntimeError(f"Embedding generation failed: {e}")
    
    def store_log(self, log_text: str, metadata: Dict[str, Any] = None) -> Dict[str, Any]:
        """Store a single log entry with embedding."""
        if not self.collection:
            raise RuntimeError("ChromaDB not initialized")
        
        try:
            # Generate embedding
            embedding = self._generate_embedding(log_text)
            
            # Create item
            log_id = str(uuid.uuid4())
            item = {
                "logId": log_id,
                "logText": log_text,
                "embedding": embedding,
                "timestamp": datetime.now().isoformat()
            }
            
            # Add custom metadata
            if metadata:
                item.update(metadata)
            
            # Store in ChromaDB
            self.collection.add(
                documents=[log_text],
                embeddings=[embedding],
                metadatas=[item],
                ids=[log_id]
            )
            
            logger.info(f"Successfully stored log item: {log_id}")
            return item
            
        except Exception as e:
            logger.error(f"Failed to store log item: {e}")
            raise RuntimeError(f"Failed to store log in ChromaDB: {e}")
    
    def ingest_logs(self, logs: List[str], metadata_list: List[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Ingest a batch of logs with embeddings."""
        if not isinstance(logs, list) or not logs:
            raise ValueError("logs must be a non-empty list of strings")
        
        if not self.collection:
            raise RuntimeError("ChromaDB not initialized")
        
        logger.info(f"Starting batch ingestion of {len(logs)} logs")
        
        documents = []
        embeddings = []
        metadatas = []
        ids = []
        stored_items = []
        
        for i, text in enumerate(logs):
            if not isinstance(text, str) or not text.strip():
                logger.warning(f"Skipping invalid log entry {i}: {text}")
                continue
            
            try:
                # Generate embedding
                embedding = self._generate_embedding(text)
                
                # Create item
                log_id = str(uuid.uuid4())
                item = {
                    "logId": log_id,
                    "logText": text,
                    "timestamp": datetime.now().isoformat()
                }
                
                # Add custom metadata if provided
                if metadata_list and i < len(metadata_list):
                    item.update(metadata_list[i])
                
                documents.append(text)
                embeddings.append(embedding)
                metadatas.append(item)
                ids.append(log_id)
                stored_items.append(item)
                
                logger.info(f"Processed log {i+1}/{len(logs)}: {log_id}")
                
            except Exception as e:
                logger.error(f"Failed to process log {i}: {e}")
                continue
        
        if not documents:
            logger.warning("No valid items to store")
            return []
        
        # Batch add to ChromaDB
        try:
            self.collection.add(
                documents=documents,
                embeddings=embeddings,
                metadatas=metadatas,
                ids=ids
            )
            
            logger.info(f"Successfully stored {len(stored_items)} log entries in ChromaDB")
            return stored_items
            
        except Exception as e:
            logger.error(f"Batch write failed: {e}")
            raise RuntimeError(f"Failed to batch write to ChromaDB: {e}")
    
    def ingest_logs_high_performance(self, logs: List[str], metadata_list: List[Dict[str, Any]] = None, max_workers: int = 4) -> Dict[str, Any]:
        """High-performance batch ingestion with parallel embedding generation."""
        if not isinstance(logs, list) or not logs:
            raise ValueError("logs must be a non-empty list of strings")
        
        if not self.collection:
            raise RuntimeError("ChromaDB not initialized")
        
        logger.info(f"Starting high-performance batch ingestion of {len(logs)} logs with {max_workers} workers")
        
        import concurrent.futures
        from concurrent.futures import ThreadPoolExecutor, as_completed
        
        documents = []
        embeddings = []
        metadatas = []
        ids = []
        failed_logs = []
        
        def process_single_log(log_data):
            """Process a single log entry and return the item data or None if failed."""
            index, text = log_data
            try:
                if not isinstance(text, str) or not text.strip():
                    logger.warning(f"Skipping invalid log entry {index}: {text}")
                    return None
                
                # Generate embedding
                embedding = self._generate_embedding(text)
                
                # Create item
                log_id = str(uuid.uuid4())
                item = {
                    "logId": log_id,
                    "logText": text,
                    "timestamp": datetime.now().isoformat()
                }
                
                # Add custom metadata if provided
                if metadata_list and index < len(metadata_list):
                    item.update(metadata_list[index])
                
                logger.debug(f"Processed log {index + 1}/{len(logs)}: {log_id}")
                return {
                    "document": text,
                    "embedding": embedding,
                    "metadata": item,
                    "id": log_id
                }
                
            except Exception as e:
                logger.error(f"Failed to process log {index}: {e}")
                failed_logs.append((index, text, str(e)))
                return None
        
        # Process embeddings in parallel
        logger.info("Generating embeddings in parallel...")
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all tasks
            future_to_index = {
                executor.submit(process_single_log, (i, text)): i 
                for i, text in enumerate(logs)
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_index):
                index = future_to_index[future]
                try:
                    result = future.result()
                    if result:
                        documents.append(result["document"])
                        embeddings.append(result["embedding"])
                        metadatas.append(result["metadata"])
                        ids.append(result["id"])
                except Exception as e:
                    logger.error(f"Exception occurred while processing log {index}: {e}")
                    failed_logs.append((index, logs[index], str(e)))
        
        if not documents:
            logger.warning("No valid items to store")
            return {
                "stored_items": [],
                "total_processed": len(logs),
                "successful": 0,
                "failed": len(failed_logs),
                "failed_details": failed_logs
            }
        
        # Report processing results
        logger.info(f"Embedding generation completed: {len(documents)} successful, {len(failed_logs)} failed")
        if failed_logs:
            logger.warning(f"Failed to process {len(failed_logs)} logs")
        
        # Batch add to ChromaDB
        try:
            self.collection.add(
                documents=documents,
                embeddings=embeddings,
                metadatas=metadatas,
                ids=ids
            )
            
            logger.info(f"Successfully stored {len(documents)} log entries in ChromaDB")
            
            # Return both successful items and failure information
            result = {
                "stored_items": metadatas,
                "total_processed": len(logs),
                "successful": len(documents),
                "failed": len(failed_logs),
                "failed_details": failed_logs
            }
            
            return result
            
        except Exception as e:
            logger.error(f"Batch write failed: {e}")
            raise RuntimeError(f"Failed to batch write to ChromaDB: {e}")
    
    def search_logs(self, query: str, top_k: int = 5, filter_metadata: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """Search logs using vector similarity."""
        if not query or not query.strip():
            raise ValueError("Query is empty.")
        
        if not self.collection:
            raise RuntimeError("ChromaDB not initialized")
        
        logger.info(f"Searching for query: '{query}' (top_k={top_k})")
        
        try:
            # Generate query embedding
            query_embedding = self._generate_embedding(query)
            
            # Perform similarity search
            results = self.collection.query(
                query_embeddings=[query_embedding],
                n_results=top_k,
                where=filter_metadata
            )
            
            # Format results
            formatted_results = []
            if results["ids"] and results["ids"][0]:
                for i, doc_id in enumerate(results["ids"][0]):
                    formatted_results.append({
                        "logId": doc_id,
                        "logText": results["documents"][0][i] if results["documents"] and results["documents"][0] else "",
                        "score": results["distances"][0][i] if results["distances"] and results["distances"][0] else 0.0,
                        "metadata": results["metadatas"][0][i] if results["metadatas"] and results["metadatas"][0] else {}
                    })
            
            logger.info(f"Search completed, found {len(formatted_results)} results")
            return formatted_results
            
        except Exception as e:
            logger.error(f"Search failed: {e}")
            raise RuntimeError(f"Search failed: {e}")
    
    def get_log_by_id(self, log_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a specific log entry by ID."""
        if not self.collection:
            raise RuntimeError("ChromaDB not initialized")
        
        try:
            results = self.collection.get(ids=[log_id])
            
            if results["ids"] and results["ids"][0]:
                return {
                    "logId": results["ids"][0],
                    "logText": results["documents"][0] if results["documents"] else "",
                    "metadata": results["metadatas"][0] if results["metadatas"] else {}
                }
            
            return None
            
        except Exception as e:
            logger.error(f"Failed to retrieve log {log_id}: {e}")
            return None
    
    def delete_log(self, log_id: str) -> bool:
        """Delete a specific log entry by ID."""
        if not self.collection:
            raise RuntimeError("ChromaDB not initialized")
        
        try:
            self.collection.delete(ids=[log_id])
            logger.info(f"Successfully deleted log: {log_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to delete log {log_id}: {e}")
            return False
    
    def get_collection_stats(self) -> Dict[str, Any]:
        """Get collection statistics."""
        if not self.collection:
            raise RuntimeError("ChromaDB not initialized")
        
        try:
            count = self.collection.count()
            return {
                "total_logs": count,
                "collection_name": self.collection_name,
                "persist_dir": self.persist_dir
            }
            
        except Exception as e:
            logger.error(f"Failed to get collection stats: {e}")
            return {}

# Global instance for backward compatibility
_log_store = None

def get_log_store() -> ChromaDBLogStore:
    """Get or create global log store instance."""
    global _log_store
    if _log_store is None:
        _log_store = ChromaDBLogStore()
    return _log_store

# Backward compatibility functions
def store_log(log_text: str) -> Dict[str, Any]:
    """Store a single log entry (backward compatibility)."""
    return get_log_store().store_log(log_text)

def ingest_logs(logs: List[str]) -> List[Dict[str, Any]]:
    """Ingest a batch of logs (backward compatibility)."""
    return get_log_store().ingest_logs(logs)

def ingest_logs_high_performance(logs: List[str], max_workers: int = 4) -> List[Dict[str, Any]]:
    """High-performance batch ingestion (backward compatibility)."""
    return get_log_store().ingest_logs_high_performance(logs, max_workers=max_workers)

def search_logs(query: str, top_k: int = 5) -> List[Dict[str, Any]]:
    """Search logs using vector similarity (backward compatibility)."""
    return get_log_store().search_logs(query, top_k)

if __name__ == "__main__":
    # Example workflow
    print("Testing ChromaDB log storage...")
    try:
        # Initialize log store
        log_store = ChromaDBLogStore()
        
        # Test batch ingestion
        print("Batch ingest logs...")
        stored = log_store.ingest_logs([
            "2025-01-01 10:00:00 INFO User login succeeded for alice from 10.0.0.1",
            "2025-01-01 10:05:10 WARN Multiple failed SSH attempts detected from 203.0.113.5",
            "2025-01-01 11:22:45 ERROR PowerShell execution blocked by AppLocker on host WIN10-01",
        ])
        print(f"Stored {len(stored)} logs successfully")

        # Test search
        print("Search: 'suspicious PowerShell execution'")
        results = log_store.search_logs("suspicious PowerShell execution", top_k=5)
        for i, r in enumerate(results, 1):
            print(f"{i}. {r.get('logId')} score={r.get('score', 0):.4f} text={r.get('logText')[:100]}...")
        
        # Test stats
        stats = log_store.get_collection_stats()
        print(f"Collection stats: {stats}")
            
    except Exception as e:
        print(f"Error: {e}")
