import os
import json
import uuid
import math
import logging
from typing import List, Dict, Any
from decimal import Decimal

import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import BotoCoreError, ClientError

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Get configuration from environment or config
_TABLE_NAME = os.getenv("DYNAMODB_TABLE_NAME", "SecurityLogs")
_REGION = os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION") or "us-east-1"
_TITAN_MODEL_ID = os.getenv("BEDROCK_EMBEDDING_MODEL", "amazon.titan-embed-text-v2:0")

logger.info(f"Initializing DynamoDB with table: {_TABLE_NAME}, region: {_REGION}")

_boto_cfg = BotoConfig(retries={"max_attempts": 10, "mode": "standard"})
ddb = boto3.resource("dynamodb", region_name=_REGION, config=_boto_cfg)
ddb_client = boto3.client("dynamodb", region_name=_REGION, config=_boto_cfg)
ddb_table = ddb.Table(_TABLE_NAME)
bedrock = boto3.client("bedrock-runtime", region_name=_REGION, config=_boto_cfg)

def _convert_floats_to_decimals(obj):
	"""Recursively convert all float values to Decimal types for DynamoDB compatibility."""
	if isinstance(obj, float):
		return Decimal(str(obj))
	elif isinstance(obj, list):
		return [_convert_floats_to_decimals(item) for item in obj]
	elif isinstance(obj, dict):
		return {key: _convert_floats_to_decimals(value) for key, value in obj.items()}
	else:
		return obj

def embed_text(text: str) -> List[float]:
	"""Generate an embedding vector for the input text using Amazon Titan Embeddings via Bedrock."""
	if not text or not text.strip():
		raise ValueError("Input text is empty.")
	
	logger.info(f"Generating embedding for text: {text[:100]}...")
	
	payload = {"inputText": text}
	try:
		resp = bedrock.invoke_model(
			modelId=_TITAN_MODEL_ID,
			body=json.dumps(payload).encode("utf-8"),
			contentType="application/json",
			accept="application/json",
		)
		body = json.loads(resp["body"].read())
		vector = body.get("embedding") or body.get("embeddings", {}).get("values")
		if not vector:
			raise RuntimeError("Titan embeddings response missing 'embedding'.")
		
		logger.info(f"Generated embedding with {len(vector)} dimensions")
		return vector
	except (BotoCoreError, ClientError) as e:
		logger.error(f"Bedrock embedding call failed: {e}")
		raise RuntimeError(f"Bedrock embedding call failed: {e}")

def store_log(log_text: str) -> Dict[str, Any]:
	"""Create an item with UUID logId, logText, and embedding; store in DynamoDB; return the item."""
	emb = embed_text(log_text)
	item = {
		"logId": str(uuid.uuid4()),
		"logText": log_text,
		"embedding": emb,
	}
	
	# Convert floats to decimals for DynamoDB compatibility
	item = _convert_floats_to_decimals(item)
	
	logger.info(f"Storing log item with ID: {item['logId']}")
	
	try:
		ddb_table.put_item(Item=item)
		logger.info(f"Successfully stored log item: {item['logId']}")
		return item
	except Exception as e:
		logger.error(f"Failed to store log item: {e}")
		raise RuntimeError(f"Failed to store log in DynamoDB: {e}")

def ingest_logs(logs: List[str]) -> List[Dict[str, Any]]:
	"""Ingest a batch of logs: embed each and batch-write to DynamoDB. Returns stored items."""
	if not isinstance(logs, list) or not logs:
		raise ValueError("logs must be a non-empty list of strings")
	
	logger.info(f"Starting batch ingestion of {len(logs)} logs")
	
	items: List[Dict[str, Any]] = []
	for i, text in enumerate(logs):
		if not isinstance(text, str) or not text.strip():
			logger.warning(f"Skipping invalid log entry {i}: {text}")
			continue
		
		try:
			emb = embed_text(text)
			item = {
				"logId": str(uuid.uuid4()), 
				"logText": text, 
				"embedding": emb
			}
			# Convert floats to decimals for DynamoDB compatibility
			item = _convert_floats_to_decimals(item)
			items.append(item)
			logger.info(f"Processed log {i+1}/{len(logs)}: {item['logId']}")
		except Exception as e:
			logger.error(f"Failed to process log {i}: {e}")
			continue

	if not items:
		logger.warning("No valid items to store")
		return []

	# Batch write with proper batching for better performance
	logger.info(f"Writing {len(items)} items to DynamoDB in batches")
	
	# DynamoDB batch write can handle up to 25 items per batch
	BATCH_SIZE = 25
	stored_items = []
	
	try:
		# Process items in batches of 25
		for i in range(0, len(items), BATCH_SIZE):
			batch_items = items[i:i + BATCH_SIZE]
			batch_num = (i // BATCH_SIZE) + 1
			total_batches = (len(items) + BATCH_SIZE - 1) // BATCH_SIZE
			
			logger.info(f"Processing batch {batch_num}/{total_batches} with {len(batch_items)} items")
			
			# Use batch_writer for efficient batch operations
			with ddb_table.batch_writer(overwrite_by_pkeys=["logId"]) as batch:
				for item in batch_items:
					batch.put_item(Item=item)
					stored_items.append(item)
					logger.debug(f"Queued item for batch write: {item['logId']}")
			
			logger.info(f"Completed batch {batch_num}/{total_batches}")
		
		logger.info(f"Successfully stored {len(stored_items)} log entries in DynamoDB using {total_batches} batches")
		return stored_items
		
	except Exception as e:
		logger.error(f"Batch write failed: {e}")
		raise RuntimeError(f"Failed to batch write to DynamoDB: {e}")

def ingest_logs_high_performance(logs: List[str], max_workers: int = 4) -> List[Dict[str, Any]]:
	"""High-performance batch ingestion with parallel embedding generation and optimized batching."""
	if not isinstance(logs, list) or not logs:
		raise ValueError("logs must be a non-empty list of strings")
	
	logger.info(f"Starting high-performance batch ingestion of {len(logs)} logs with {max_workers} workers")
	
	import concurrent.futures
	from concurrent.futures import ThreadPoolExecutor, as_completed
	
	# Process embeddings in parallel for better performance
	items: List[Dict[str, Any]] = []
	failed_logs = []
	
	def process_single_log(log_data):
		"""Process a single log entry and return the item or None if failed."""
		index, text = log_data
		try:
			if not isinstance(text, str) or not text.strip():
				logger.warning(f"Skipping invalid log entry {index}: {text}")
				return None
			
			emb = embed_text(text)
			item = {
				"logId": str(uuid.uuid4()), 
				"logText": text, 
				"embedding": emb
			}
			# Convert floats to decimals for DynamoDB compatibility
			item = _convert_floats_to_decimals(item)
			logger.debug(f"Processed log {index + 1}/{len(logs)}: {item['logId']}")
			return item
			
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
				item = future.result()
				if item:
					items.append(item)
			except Exception as e:
				logger.error(f"Exception occurred while processing log {index}: {e}")
				failed_logs.append((index, logs[index], str(e)))
	
	if not items:
		logger.warning("No valid items to store")
		return []
	
	# Report processing results
	logger.info(f"Embedding generation completed: {len(items)} successful, {len(failed_logs)} failed")
	if failed_logs:
		logger.warning(f"Failed to process {len(failed_logs)} logs")
	
	# Optimized batch writing
	logger.info(f"Writing {len(items)} items to DynamoDB using optimized batching")
	
	# DynamoDB batch write can handle up to 25 items per batch
	BATCH_SIZE = 25
	stored_items = []
	
	try:
		# Process items in batches of 25
		for i in range(0, len(items), BATCH_SIZE):
			batch_items = items[i:i + BATCH_SIZE]
			batch_num = (i // BATCH_SIZE) + 1
			total_batches = (len(items) + BATCH_SIZE - 1) // BATCH_SIZE
			
			logger.info(f"Processing batch {batch_num}/{total_batches} with {len(batch_items)} items")
			
			# Use batch_writer for efficient batch operations
			with ddb_table.batch_writer(overwrite_by_pkeys=["logId"]) as batch:
				for item in batch_items:
					batch.put_item(Item=item)
					stored_items.append(item)
					logger.debug(f"Queued item for batch write: {item['logId']}")
			
			logger.info(f"Completed batch {batch_num}/{total_batches}")
		
		logger.info(f"Successfully stored {len(stored_items)} log entries in DynamoDB using {total_batches} batches")
		
		# Return both successful items and failure information
		result = {
			"stored_items": stored_items,
			"total_processed": len(logs),
			"successful": len(stored_items),
			"failed": len(failed_logs),
			"failed_details": failed_logs
		}
		
		return result
		
	except Exception as e:
		logger.error(f"Batch write failed: {e}")
		raise RuntimeError(f"Failed to batch write to DynamoDB: {e}")

def ingest_logs_high_performance(logs: List[str], max_workers: int = 4) -> List[Dict[str, Any]]:
	"""High-performance batch ingestion with parallel embedding generation and optimized batching."""
	if not isinstance(logs, list) or not logs:
		raise ValueError("logs must be a non-empty list of strings")
	
	logger.info(f"Starting high-performance batch ingestion of {len(logs)} logs with {max_workers} workers")
	
	import concurrent.futures
	from concurrent.futures import ThreadPoolExecutor, as_completed
	
	# Process embeddings in parallel for better performance
	items: List[Dict[str, Any]] = []
	failed_logs = []
	
	def process_single_log(log_data):
		"""Process a single log entry and return the item or None if failed."""
		index, text = log_data
		try:
			if not isinstance(text, str) or not text.strip():
				logger.warning(f"Skipping invalid log entry {index}: {text}")
				return None
			
			emb = embed_text(text)
			item = {
				"logId": str(uuid.uuid4()), 
				"logText": text, 
				"embedding": emb
			}
			# Convert floats to decimals for DynamoDB compatibility
			item = _convert_floats_to_decimals(item)
			logger.debug(f"Processed log {index + 1}/{len(logs)}: {item['logId']}")
			return item
			
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
				item = future.result()
				if item:
					items.append(item)
			except Exception as e:
				logger.error(f"Exception occurred while processing log {index}: {e}")
				failed_logs.append((index, logs[index], str(e)))
	
	if not items:
		logger.warning("No valid items to store")
		return []
	
	# Report processing results
	logger.info(f"Embedding generation completed: {len(items)} successful, {len(failed_logs)} failed")
	if failed_logs:
		logger.warning(f"Failed to process {len(failed_logs)} logs")
	
	# Optimized batch writing
	logger.info(f"Writing {len(items)} items to DynamoDB using optimized batching")
	
	# DynamoDB batch write can handle up to 25 items per batch
	BATCH_SIZE = 25
	stored_items = []
	
	try:
		# Process items in batches of 25
		for i in range(0, len(items), BATCH_SIZE):
			batch_items = items[i:i + BATCH_SIZE]
			batch_num = (i // BATCH_SIZE) + 1
			total_batches = (len(items) + BATCH_SIZE - 1) // BATCH_SIZE
			
			logger.info(f"Processing batch {batch_num}/{total_batches} with {len(batch_items)} items")
			
			# Use batch_writer for efficient batch operations
			with ddb_table.batch_writer(overwrite_by_pkeys=["logId"]) as batch:
				for item in batch_items:
					batch.put_item(Item=item)
					stored_items.append(item)
					logger.debug(f"Queued item for batch write: {item['logId']}")
			
			logger.info(f"Completed batch {batch_num}/{total_batches}")
		
		logger.info(f"Successfully stored {len(stored_items)} log entries in DynamoDB using {total_batches} batches")
		
		# Return both successful items and failure information
		result = {
			"stored_items": stored_items,
			"total_processed": len(logs),
			"successful": len(stored_items),
			"failed": len(failed_logs),
			"failed_details": failed_logs
		}
		
		return result
		
	except Exception as e:
		logger.error(f"Batch write failed: {e}")
		raise RuntimeError(f"Failed to batch write to DynamoDB: {e}")

def _cosine_similarity(vec_a: List, vec_b: List) -> float:
	"""Calculate cosine similarity between two vectors, handling both float and Decimal types."""
	if len(vec_a) != len(vec_b):
		raise ValueError("Vectors must have the same length for cosine similarity.")
	
	# Convert all values to float for calculations
	vec_a_float = [float(x) for x in vec_a]
	vec_b_float = [float(x) for x in vec_b]
	
	norm_a = math.sqrt(sum(x * x for x in vec_a_float))
	norm_b = math.sqrt(sum(y * y for y in vec_b_float))
	if norm_a == 0.0 or norm_b == 0.0:
		return 0.0
	dot = sum(x * y for x, y in zip(vec_a_float, vec_b_float))
	return dot / (norm_a * norm_b)

def _scan_and_rank(query_vec: List[float], top_k: int) -> List[Dict[str, Any]]:
	"""Scan DynamoDB and rank by cosine similarity."""
	logger.info(f"Scanning DynamoDB for vector similarity search (top_k={top_k})")
	
	results: List[Dict[str, Any]] = []
	kwargs: Dict[str, Any] = {
		"ProjectionExpression": "#i, #t, #e",
		"ExpressionAttributeNames": {"#i": "logId", "#t": "logText", "#e": "embedding"},
	}
	
	scan_count = 0
	while True:
		resp = ddb_table.scan(**kwargs)
		scan_count += 1
		logger.info(f"Scan {scan_count}: Retrieved {len(resp.get('Items', []))} items")
		
		for item in resp.get("Items", []):
			item_vec = item.get("embedding") or []
			try:
				# Convert Decimal values back to float for calculations
				item_vec_float = [float(v) for v in item_vec]
				score = _cosine_similarity(query_vec, item_vec_float)
				results.append({
					"logId": item.get("logId"), 
					"logText": item.get("logText"), 
					"score": score
				})
			except (ValueError, TypeError) as e:
				logger.warning(f"Invalid embedding for item {item.get('logId')}: {e}")
				continue
		
		last_key = resp.get("LastEvaluatedKey")
		if not last_key:
			break
		kwargs["ExclusiveStartKey"] = last_key
	
	logger.info(f"Total items scanned: {len(results)}")
	results.sort(key=lambda r: r["score"], reverse=True)
	return results[: max(1, top_k)]

def search_logs(query: str, top_k: int = 5) -> List[Dict[str, Any]]:
	"""Embed the query and perform vector similarity search using scan + cosine similarity."""
	if not query or not query.strip():
		raise ValueError("Query is empty.")
	
	logger.info(f"Searching for query: '{query}' (top_k={top_k})")
	
	try:
		q_vec = embed_text(query)
		logger.info(f"Generated query embedding with {len(q_vec)} dimensions")
		
		# Use scan + cosine similarity (more reliable than native vector search)
		results = _scan_and_rank(q_vec, top_k)
		
		logger.info(f"Search completed, found {len(results)} results")
		return results
		
	except Exception as e:
		logger.error(f"Search failed: {e}")
		raise RuntimeError(f"Search failed: {e}")

if __name__ == "__main__":
	# Example workflow
	print("Batch ingest logs...")
	try:
		stored = ingest_logs([
			"2025-01-01 10:00:00 INFO User login succeeded for alice from 10.0.0.1",
			"2025-01-01 10:05:10 WARN Multiple failed SSH attempts detected from 203.0.113.5",
			"2025-01-01 11:22:45 ERROR PowerShell execution blocked by AppLocker on host WIN10-01",
		])
		print(f"Stored {len(stored)} logs successfully")

		print("Search: 'suspicious PowerShell execution'")
		res = search_logs("suspicious PowerShell execution", top_k=5)
		for i, r in enumerate(res, 1):
			print(f"{i}. {r.get('logId')} score={r.get('score', 0):.4f} text={r.get('logText')[:100]}...")
			
	except Exception as e:
		print(f"Error: {e}")
