"""
RAG (Retrieval-Augmented Generation) Module for enriching analysis with context.
"""
import os
from typing import List, Dict, Any, Optional
from datetime import datetime
from pathlib import Path
from loguru import logger

# Vector database and RAG imports
try:
    import chromadb
    from chromadb.config import Settings
except ImportError:
    logger.warning("ChromaDB not available")
    chromadb = None

# AWS SDK for Kendra integration
try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError:
    logger.warning("Boto3 not available for AWS integration")
    boto3 = None

# LangChain for RAG pipeline
try:
    from langchain.chains import RetrievalQA
    from langchain_community.embeddings import HuggingFaceEmbeddings
    from langchain_community.vectorstores import Chroma
    from langchain.docstore.document import Document
    from langchain.text_splitter import RecursiveCharacterTextSplitter
except ImportError:
    logger.warning("LangChain not available")
    RetrievalQA = None

from data_models import InitialAnalysis, EnrichmentData, EnrichedAnalysis, SeverityLevel
from config import Config

class LocalKnowledgeBase:
    """Local vector database using ChromaDB for cybersecurity knowledge."""
    
    def __init__(self, persist_dir: str = None):
        self.persist_dir = persist_dir or Config.CHROMA_PERSIST_DIR
        self.client = None
        self.collection = None
        self._initialize_db()
    
    def _initialize_db(self):
        """Initialize ChromaDB client and collection."""
        if not chromadb:
            logger.warning("ChromaDB not available")
            return
        
        try:
            # Create persistent ChromaDB client
            self.client = chromadb.PersistentClient(path=self.persist_dir)
            
            # Get or create collection
            self.collection = self.client.get_or_create_collection(
                name="cybersecurity_knowledge",
                metadata={"hnsw:space": "cosine"}
            )
            
            # Populate with sample data if empty
            if self.collection.count() == 0:
                self._populate_sample_data()
            
            logger.info(f"ChromaDB initialized with {self.collection.count()} documents")
            
        except Exception as e:
            logger.error(f"Failed to initialize ChromaDB: {e}")
            self.client = None
            self.collection = None
    
    def _populate_sample_data(self):
        """Populate database with sample cybersecurity knowledge."""
        sample_documents = [
            {
                "id": "mitre_t1078",
                "content": "T1078 Valid Accounts: Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Common indicators include unusual login times, multiple failed attempts, and geographic anomalies.",
                "metadata": {"type": "mitre_technique", "technique_id": "T1078"}
            },
            {
                "id": "lateral_movement_patterns",
                "content": "Lateral Movement Indicators: Look for patterns such as SMB/RDP connections between internal hosts, service account authentication across multiple systems, and use of administrative tools like PsExec, WMI, or PowerShell remoting.",
                "metadata": {"type": "detection_pattern", "category": "lateral_movement"}
            },
            {
                "id": "powershell_attacks",
                "content": "PowerShell Attack Indicators: Encoded commands (base64), execution policy bypass, download cradles (IEX, wget), fileless malware execution, and suspicious script block logging events.",
                "metadata": {"type": "detection_pattern", "category": "execution"}
            },
            {
                "id": "network_anomalies",
                "content": "Network Anomaly Detection: Unusual DNS queries, connections to known bad IPs, large data transfers, beacon-like traffic patterns, and communication with newly registered domains.",
                "metadata": {"type": "detection_pattern", "category": "network"}
            },
            {
                "id": "persistence_mechanisms",
                "content": "Common Persistence Mechanisms: Registry Run keys, scheduled tasks, WMI event subscriptions, service creation, DLL hijacking, and startup folder modifications.",
                "metadata": {"type": "detection_pattern", "category": "persistence"}
            }
        ]
        
        try:
            documents = [doc["content"] for doc in sample_documents]
            metadatas = [doc["metadata"] for doc in sample_documents]
            ids = [doc["id"] for doc in sample_documents]
            
            self.collection.add(
                documents=documents,
                metadatas=metadatas,
                ids=ids
            )
            
            logger.info("Populated ChromaDB with sample cybersecurity knowledge")
            
        except Exception as e:
            logger.error(f"Error populating sample data: {e}")
    
    def query(self, query_text: str, n_results: int = 3) -> List[Dict[str, Any]]:
        """Query the local knowledge base for relevant documents."""
        if not self.collection:
            return []
        
        try:
            results = self.collection.query(
                query_texts=[query_text],
                n_results=n_results
            )
            
            # Format results
            formatted_results = []
            for i in range(len(results['documents'][0])):
                formatted_results.append({
                    'content': results['documents'][0][i],
                    'metadata': results['metadatas'][0][i],
                    'distance': results['distances'][0][i] if 'distances' in results else 0.0
                })
            
            logger.debug(f"Local KB query returned {len(formatted_results)} results")
            return formatted_results
            
        except Exception as e:
            logger.error(f"Error querying local knowledge base: {e}")
            return []
    
    def add_document(self, content: str, metadata: Dict[str, Any], doc_id: str = None):
        """Add a new document to the knowledge base."""
        if not self.collection:
            return
        
        try:
            doc_id = doc_id or f"doc_{datetime.now().timestamp()}"
            
            self.collection.add(
                documents=[content],
                metadatas=[metadata],
                ids=[doc_id]
            )
            
            logger.debug(f"Added document {doc_id} to knowledge base")
            
        except Exception as e:
            logger.error(f"Error adding document to knowledge base: {e}")

class EnterpriseRetrieval:
    """Enterprise-scale retrieval using AWS Kendra."""
    
    def __init__(self):
        self.kendra_client = None
        self.index_id = Config.KENDRA_INDEX_ID
        self._initialize_kendra()
    
    def _initialize_kendra(self):
        """Initialize AWS Kendra client."""
        if not boto3 or not self.index_id or len(str(self.index_id)) < 36:
            logger.warning("AWS Kendra not configured or boto3 not available")
            return
        
        try:
            self.kendra_client = boto3.client(
                'kendra',
                region_name=Config.AWS_REGION,
                aws_access_key_id=Config.AWS_ACCESS_KEY_ID,
                aws_secret_access_key=Config.AWS_SECRET_ACCESS_KEY
            )
            
            logger.info("AWS Kendra client initialized")
            
        except Exception as e:
            logger.error(f"Failed to initialize Kendra client: {e}")
            self.kendra_client = None
    
    def query(self, query_text: str, max_results: int = 5) -> List[Dict[str, Any]]:
        """Query AWS Kendra for relevant documents."""
        if not self.kendra_client:
            logger.warning("Kendra client not available, returning empty results")
            return []
        
        try:
            response = self.kendra_client.query(
                IndexId=self.index_id,
                QueryText=query_text,
                PageSize=max_results
            )
            
            # Format Kendra results
            formatted_results = []
            for item in response.get('ResultItems', []):
                formatted_results.append({
                    'title': item.get('DocumentTitle', ''),
                    'excerpt': item.get('DocumentExcerpt', ''),
                    'uri': item.get('DocumentURI', ''),
                    'confidence': item.get('ScoreAttributes', {}).get('ScoreConfidence', 'LOW'),
                    'type': item.get('Type', 'DOCUMENT')
                })
            
            logger.debug(f"Kendra query returned {len(formatted_results)} results")
            return formatted_results
            
        except ClientError as e:
            logger.error(f"Kendra query error: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error querying Kendra: {e}")
            return []

class RAGPipeline:
    """Main RAG pipeline orchestrator using LangChain."""
    
    def __init__(self):
        self.local_kb = LocalKnowledgeBase()
        self.enterprise_retrieval = EnterpriseRetrieval()
        self.text_splitter = None
        self._initialize_components()
    
    def _initialize_components(self):
        """Initialize RAG pipeline components."""
        try:
            if RetrievalQA:
                self.text_splitter = RecursiveCharacterTextSplitter(
                    chunk_size=1000,
                    chunk_overlap=200
                )
            logger.info("RAG pipeline components initialized")
        except Exception as e:
            logger.error(f"Error initializing RAG components: {e}")
    
    def enrich_analysis(self, initial_analysis: InitialAnalysis) -> EnrichedAnalysis:
        """
        Enrich initial analysis with context from multiple sources.
        
        Args:
            initial_analysis: Initial analysis from LLM
            
        Returns:
            EnrichedAnalysis with additional context
        """
        logger.info("Starting RAG enrichment process")
        
        enrichments = []
        
        try:
            # Query local knowledge base
            local_enrichments = self._query_local_knowledge(initial_analysis)
            enrichments.extend(local_enrichments)
            
            # Query enterprise sources
            enterprise_enrichments = self._query_enterprise_sources(initial_analysis)
            enrichments.extend(enterprise_enrichments)
            
            # Generate enhanced summary
            enhanced_summary = self._generate_enhanced_summary(initial_analysis, enrichments)
            
            # Reconstruct attack chain
            attack_chain = self._reconstruct_attack_chain(initial_analysis, enrichments)
            
            # Generate recommendations
            recommendations = self._generate_recommendations(initial_analysis, enrichments)
            
            enriched_analysis = EnrichedAnalysis(
                initial_analysis=initial_analysis,
                enrichments=enrichments,
                enhanced_summary=enhanced_summary,
                attack_chain=attack_chain,
                recommendations=recommendations
            )
            
            logger.info("RAG enrichment completed successfully")
            return enriched_analysis
            
        except Exception as e:
            logger.error(f"Error during RAG enrichment: {e}")
            # Return minimal enriched analysis on error
            return EnrichedAnalysis(
                initial_analysis=initial_analysis,
                enrichments=[],
                enhanced_summary=initial_analysis.summary,
                attack_chain=["Analysis enrichment failed"],
                recommendations=["Review logs manually for additional context"]
            )
    
    def _query_local_knowledge(self, analysis: InitialAnalysis) -> List[EnrichmentData]:
        """Query local knowledge base for context."""
        enrichments = []
        
        try:
            # Create queries based on analysis findings
            queries = []
            
            # Query based on MITRE mappings
            for mapping in analysis.mitre_mappings:
                queries.append(f"{mapping.tactic_name} {mapping.technique_name}")
            
            # Query based on IOCs
            for ioc in analysis.iocs:
                queries.append(f"{ioc.type} {ioc.value}")
            
            # Query based on suspicious patterns
            for pattern in analysis.suspicious_patterns[:3]:  # Limit queries
                queries.append(pattern)
            
            # Execute queries
            for query in queries[:5]:  # Limit total queries
                results = self.local_kb.query(query, n_results=2)
                
                for result in results:
                    enrichment = EnrichmentData(
                        source="local_knowledge_base",
                        ioc_value=query,
                        additional_context={
                            "content": result["content"],
                            "metadata": result["metadata"],
                            "relevance_score": 1.0 - result["distance"]
                        },
                        last_updated=datetime.now()
                    )
                    enrichments.append(enrichment)
            
            logger.debug(f"Local KB enrichment added {len(enrichments)} entries")
            
        except Exception as e:
            logger.error(f"Error querying local knowledge base: {e}")
        
        return enrichments
    
    def _query_enterprise_sources(self, analysis: InitialAnalysis) -> List[EnrichmentData]:
        """Query enterprise sources for context."""
        enrichments = []
        
        try:
            # Create enterprise queries
            enterprise_queries = []
            
            # Query for IOCs
            for ioc in analysis.iocs:
                if ioc.confidence > 0.5:  # Only high-confidence IOCs
                    enterprise_queries.append(f"security incident {ioc.value}")
            
            # Query for MITRE techniques
            for mapping in analysis.mitre_mappings:
                if mapping.confidence > 0.5:
                    enterprise_queries.append(f"attack technique {mapping.technique_name}")
            
            # Execute enterprise queries
            for query in enterprise_queries[:3]:  # Limit queries
                results = self.enterprise_retrieval.query(query, max_results=2)
                
                for result in results:
                    enrichment = EnrichmentData(
                        source="enterprise_kendra",
                        ioc_value=query,
                        additional_context={
                            "title": result.get("title", ""),
                            "excerpt": result.get("excerpt", ""),
                            "uri": result.get("uri", ""),
                            "confidence": result.get("confidence", "LOW")
                        },
                        last_updated=datetime.now()
                    )
                    enrichments.append(enrichment)
            
            logger.debug(f"Enterprise enrichment added {len(enrichments)} entries")
            
        except Exception as e:
            logger.error(f"Error querying enterprise sources: {e}")
        
        return enrichments
    
    def _generate_enhanced_summary(self, analysis: InitialAnalysis, enrichments: List[EnrichmentData]) -> str:
        """Generate enhanced summary incorporating enrichment data."""
        try:
            enhanced_parts = [analysis.summary]
            
            # Add context from enrichments
            if enrichments:
                enhanced_parts.append("\nAdditional Context:")
                
                local_contexts = [e for e in enrichments if e.source == "local_knowledge_base"]
                if local_contexts:
                    enhanced_parts.append("- Knowledge base indicates:")
                    for ctx in local_contexts[:2]:  # Limit context
                        content = ctx.additional_context.get("content", "")[:200]
                        enhanced_parts.append(f"  • {content}...")
                
                enterprise_contexts = [e for e in enrichments if e.source == "enterprise_kendra"]
                if enterprise_contexts:
                    enhanced_parts.append("- Enterprise sources indicate:")
                    for ctx in enterprise_contexts[:2]:
                        excerpt = ctx.additional_context.get("excerpt", "")[:200]
                        enhanced_parts.append(f"  • {excerpt}...")
            
            return "\n".join(enhanced_parts)
            
        except Exception as e:
            logger.error(f"Error generating enhanced summary: {e}")
            return analysis.summary
    
    def _reconstruct_attack_chain(self, analysis: InitialAnalysis, enrichments: List[EnrichmentData]) -> List[str]:
        """Reconstruct potential attack chain from analysis and enrichments."""
        try:
            attack_chain = []
            
            # Sort MITRE mappings by typical attack progression
            tactic_order = {
                "Initial Access": 1, "Execution": 2, "Persistence": 3,
                "Privilege Escalation": 4, "Defense Evasion": 5,
                "Credential Access": 6, "Discovery": 7, "Lateral Movement": 8,
                "Collection": 9, "Exfiltration": 10, "Impact": 11
            }
            
            sorted_mappings = sorted(
                analysis.mitre_mappings,
                key=lambda x: tactic_order.get(x.tactic_name, 99)
            )
            
            for mapping in sorted_mappings:
                step = f"{mapping.tactic_name}"
                if mapping.technique_name:
                    step += f" via {mapping.technique_name}"
                attack_chain.append(step)
            
            # Add IOC context
            if analysis.iocs:
                high_conf_iocs = [ioc for ioc in analysis.iocs if ioc.confidence > 0.7]
                if high_conf_iocs:
                    ioc_summary = f"Key indicators: {', '.join([f'{ioc.type}:{ioc.value}' for ioc in high_conf_iocs[:3]])}"
                    attack_chain.append(ioc_summary)
            
            return attack_chain if attack_chain else ["Attack chain reconstruction incomplete"]
            
        except Exception as e:
            logger.error(f"Error reconstructing attack chain: {e}")
            return ["Attack chain analysis failed"]
    
    def _generate_recommendations(self, analysis: InitialAnalysis, enrichments: List[EnrichmentData]) -> List[str]:
        """Generate security recommendations based on analysis."""
        recommendations = []
        
        try:
            # Severity-based recommendations
            if analysis.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]:
                recommendations.extend([
                    "Immediately isolate affected systems from the network",
                    "Change passwords for all potentially compromised accounts",
                    "Review and update firewall rules to block malicious IPs"
                ])
            
            # IOC-based recommendations
            ip_iocs = [ioc for ioc in analysis.iocs if ioc.type == "ip"]
            if ip_iocs:
                recommendations.append(f"Block {len(ip_iocs)} suspicious IP addresses in firewall")
            
            domain_iocs = [ioc for ioc in analysis.iocs if ioc.type == "domain"]
            if domain_iocs:
                recommendations.append(f"Add {len(domain_iocs)} domains to DNS blacklist")
            
            # MITRE-based recommendations
            for mapping in analysis.mitre_mappings:
                if mapping.tactic_name == "Persistence":
                    recommendations.append("Review startup items and scheduled tasks")
                elif mapping.tactic_name == "Lateral Movement":
                    recommendations.append("Audit administrative account usage")
                elif mapping.tactic_name == "Data Exfiltration":
                    recommendations.append("Monitor outbound network traffic")
            
            # General recommendations
            recommendations.extend([
                "Update endpoint detection and response (EDR) rules",
                "Review system logs for additional indicators",
                "Document findings for future reference"
            ])
            
            return recommendations[:10]  # Limit recommendations
            
        except Exception as e:
            logger.error(f"Error generating recommendations: {e}")
            return ["Manual review recommended due to analysis error"]