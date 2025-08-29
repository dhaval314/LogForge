#!/usr/bin/env python3
"""
Debug script to identify what's causing RAG enrichment to hang.
Run this to test individual components of the RAG pipeline.
"""
import os
import sys
import time
import traceback
from pathlib import Path

# Add the current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from loguru import logger
from config import Config

def test_chromadb_connection():
    """Test ChromaDB connection and basic operations."""
    print("🔍 Testing ChromaDB Connection...")
    
    try:
        import chromadb
        from chromadb.config import Settings
        
        # Test client creation
        print("  Creating ChromaDB client...")
        client = chromadb.PersistentClient(path=Config.CHROMA_PERSIST_DIR)
        print("  ✅ ChromaDB client created successfully")
        
        # Test collection creation
        print("  Creating test collection...")
        collection = client.get_or_create_collection(
            name="test_collection",
            metadata={"hnsw:space": "cosine"}
        )
        print("  ✅ Test collection created successfully")
        
        # Test basic operations
        print("  Testing basic operations...")
        collection.add(
            documents=["This is a test document"],
            metadatas=[{"type": "test"}],
            ids=["test_id_1"]
        )
        print("  ✅ Document added successfully")
        
        # Test query
        print("  Testing query...")
        results = collection.query(
            query_texts=["test document"],
            n_results=1
        )
        print(f"  ✅ Query successful, returned {len(results['ids'][0])} results")
        
        # Cleanup
        client.delete_collection("test_collection")
        print("  ✅ Test collection cleaned up")
        
        return True
        
    except Exception as e:
        print(f"  ❌ ChromaDB test failed: {e}")
        traceback.print_exc()
        return False

def test_rag_pipeline():
    """Test RAG pipeline components."""
    print("\n🔍 Testing RAG Pipeline Components...")
    
    try:
        from rag_enrichment import LocalKnowledgeBase, EnterpriseRetrieval, RAGPipeline
        
        # Test LocalKnowledgeBase
        print("  Testing LocalKnowledgeBase...")
        local_kb = LocalKnowledgeBase()
        results = local_kb.query("mitre attack", n_results=2)
        print(f"  ✅ LocalKnowledgeBase query returned {len(results)} results")
        
        # Test EnterpriseRetrieval
        print("  Testing EnterpriseRetrieval...")
        enterprise = EnterpriseRetrieval()
        results = enterprise.query("security log", max_results=2)
        print(f"  ✅ EnterpriseRetrieval query returned {len(results)} results")
        
        # Test RAGPipeline initialization
        print("  Testing RAGPipeline initialization...")
        rag = RAGPipeline()
        print("  ✅ RAGPipeline initialized successfully")
        
        return True
        
    except Exception as e:
        print(f"  ❌ RAG pipeline test failed: {e}")
        traceback.print_exc()
        return False

def test_llm_analysis():
    """Test LLM analysis components."""
    print("\n🔍 Testing LLM Analysis Components...")
    
    try:
        from llm_analysis import GraniteAnalyzer
        
        # Test analyzer initialization
        print("  Testing GraniteAnalyzer initialization...")
        analyzer = GraniteAnalyzer()
        print("  ✅ GraniteAnalyzer initialized successfully")
        
        # Test with a simple log entry
        print("  Testing simple log analysis...")
        test_log = "2025-01-01 10:00:00 INFO User login succeeded for alice from 10.0.0.1"
        
        # Just test initialization, don't actually run analysis
        print("  ✅ LLM components ready (skipping actual analysis for speed)")
        
        return True
        
    except Exception as e:
        print(f"  ❌ LLM analysis test failed: {e}")
        traceback.print_exc()
        return False

def test_agents():
    """Test agent components."""
    print("\n🔍 Testing Agent Components...")
    
    try:
        from agents import ForensicOrchestrator
        
        # Test orchestrator initialization
        print("  Testing ForensicOrchestrator initialization...")
        orchestrator = ForensicOrchestrator()
        print("  ✅ ForensicOrchestrator initialized successfully")
        
        return True
        
    except Exception as e:
        print(f"  ❌ Agent test failed: {e}")
        traceback.print_exc()
        return False

def test_s3_integration():
    """Test S3 integration."""
    print("\n🔍 Testing S3 Integration...")
    
    try:
        from aws_s3_utils import is_s3_available, get_s3_utils
        
        # Test S3 availability
        s3_available = is_s3_available()
        print(f"  S3 Available: {'✅ Yes' if s3_available else '❌ No'}")
        
        if s3_available:
            s3_utils = get_s3_utils()
            print(f"  S3 Bucket: {s3_utils.bucket_name}")
            print(f"  S3 Configured: {'✅ Yes' if s3_utils.is_configured else '❌ No'}")
        
        return True
        
    except Exception as e:
        print(f"  ❌ S3 test failed: {e}")
        traceback.print_exc()
        return False

def main():
    """Run all diagnostic tests."""
    print("🔧 LogForge RAG Hang Diagnostic Tool")
    print("=" * 50)
    
    tests = [
        ("ChromaDB Connection", test_chromadb_connection),
        ("RAG Pipeline", test_rag_pipeline),
        ("LLM Analysis", test_llm_analysis),
        ("Agents", test_agents),
        ("S3 Integration", test_s3_integration),
    ]
    
    results = {}
    
    for test_name, test_func in tests:
        try:
            start_time = time.time()
            success = test_func()
            elapsed_time = time.time() - start_time
            results[test_name] = {
                "success": success,
                "time": elapsed_time
            }
            print(f"  ⏱️  {test_name} took {elapsed_time:.2f} seconds")
        except Exception as e:
            print(f"  ❌ {test_name} failed with exception: {e}")
            results[test_name] = {
                "success": False,
                "time": 0,
                "error": str(e)
            }
    
    # Summary
    print("\n📊 Diagnostic Summary")
    print("=" * 50)
    
    for test_name, result in results.items():
        status = "✅ PASS" if result["success"] else "❌ FAIL"
        time_str = f"({result['time']:.2f}s)" if result["success"] else ""
        print(f"{status} {test_name} {time_str}")
        
        if not result["success"] and "error" in result:
            print(f"    Error: {result['error']}")
    
    # Recommendations
    print("\n💡 Recommendations")
    print("=" * 50)
    
    if not results["ChromaDB Connection"]["success"]:
        print("• ChromaDB connection failed - check your ChromaDB configuration")
        print("• Try running: pip install chromadb")
        print("• Check if ChromaDB directory exists and is writable")
    
    if not results["RAG Pipeline"]["success"]:
        print("• RAG pipeline failed - this is likely the source of the hang")
        print("• Check ChromaDB logs for errors")
        print("• Verify all required dependencies are installed")
    
    if not results["LLM Analysis"]["success"]:
        print("• LLM analysis failed - check your LLM provider configuration")
        print("• Verify API keys are set correctly")
        print("• Check network connectivity to LLM services")
    
    if results["RAG Pipeline"]["success"] and results["RAG Pipeline"]["time"] > 10:
        print("• RAG pipeline is slow - consider reducing query limits")
        print("• Check ChromaDB performance and indexing")
    
    print("\n🎯 Next Steps")
    print("=" * 50)
    print("1. If ChromaDB is failing, fix the database connection first")
    print("2. If RAG pipeline is slow, try with smaller log files")
    print("3. If LLM analysis is timing out, check your API configuration")
    print("4. Run the app with LOG_LEVEL=DEBUG for more detailed logs")

if __name__ == "__main__":
    main()
