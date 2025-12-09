"""
Git Committer MCP Server - The Mouthpiece
Creates professionally formatted pull requests
"""

import asyncio
from typing import Any, Dict, List, Optional
from datetime import datetime
from github import Github, GithubException
from git import Repo
import tempfile
import shutil
from pathlib import Path

from helios.mcp_protocol import (
    MCPServer,
    MCPServerInfo,
    MCPToolParameter,
)
from helios.logging_config import get_logger

logger = get_logger(__name__)


class GitCommitterServer(MCPServer):
    """MCP Server for Git operations and PR creation"""
    
    def __init__(self, github_token: str):
        server_info = MCPServerInfo(
            name="Git Committer",
            version="1.0.0",
            description="Creates professionally formatted pull requests and manages Git operations",
            capabilities=["pr_creation", "branch_management", "commit_operations"]
        )
        super().__init__(server_info)
        
        self.github_token = github_token
        self.github = Github(github_token)
        
        # Register tools
        self._register_tools()
    
    def _register_tools(self) -> None:
        """Register all Git Committer tools"""
        
        # Tool 1: Create pull request
        self.tool_registry.register_tool(
            name="tools.github.create_pull_request",
            description="Creates a pull request with a code patch",
            parameters=[
                MCPToolParameter(
                    name="repo_name",
                    type="string",
                    description="Repository name in format 'owner/repo'",
                    required=True
                ),
                MCPToolParameter(
                    name="branch_name",
                    type="string",
                    description="Name for the new branch",
                    required=True
                ),
                MCPToolParameter(
                    name="title",
                    type="string",
                    description="Pull request title",
                    required=True
                ),
                MCPToolParameter(
                    name="body",
                    type="string",
                    description="Pull request description",
                    required=True
                ),
                MCPToolParameter(
                    name="patch_data",
                    type="string",
                    description="Git patch to apply",
                    required=True
                ),
                MCPToolParameter(
                    name="base_branch",
                    type="string",
                    description="Base branch to merge into",
                    required=False,
                    default="main"
                )
            ],
            handler=self.create_pull_request,
            category="pr"
        )
        
        # Tool 2: Create branch
        self.tool_registry.register_tool(
            name="tools.github.create_branch",
            description="Creates a new branch in a repository",
            parameters=[
                MCPToolParameter(
                    name="repo_name",
                    type="string",
                    description="Repository name in format 'owner/repo'",
                    required=True
                ),
                MCPToolParameter(
                    name="branch_name",
                    type="string",
                    description="Name for the new branch",
                    required=True
                ),
                MCPToolParameter(
                    name="source_branch",
                    type="string",
                    description="Source branch to create from",
                    required=False,
                    default="main"
                )
            ],
            handler=self.create_branch,
            category="git"
        )
        
        # Tool 3: Generate PR body from CVE
        self.tool_registry.register_tool(
            name="tools.github.generate_pr_body",
            description="Generates a professional PR description for a security patch",
            parameters=[
                MCPToolParameter(
                    name="cve_id",
                    type="string",
                    description="CVE identifier",
                    required=True
                ),
                MCPToolParameter(
                    name="cve_description",
                    type="string",
                    description="CVE description",
                    required=True
                ),
                MCPToolParameter(
                    name="remediation",
                    type="string",
                    description="Remediation summary",
                    required=True
                ),
                MCPToolParameter(
                    name="test_results",
                    type="string",
                    description="Sandbox test results",
                    required=False
                )
            ],
            handler=self.generate_pr_body,
            category="generation"
        )
        
        # Tool 4: Fork repository
        self.tool_registry.register_tool(
            name="tools.github.fork_repository",
            description="Forks a repository to the authenticated user's account",
            parameters=[
                MCPToolParameter(
                    name="repo_name",
                    type="string",
                    description="Repository name in format 'owner/repo'",
                    required=True
                )
            ],
            handler=self.fork_repository,
            category="git"
        )
    
    async def create_pull_request(
        self,
        repo_name: str,
        branch_name: str,
        title: str,
        body: str,
        patch_data: str,
        base_branch: str = "main"
    ) -> Dict[str, Any]:
        """Create a pull request with a code patch"""
        logger.info(f"Creating PR for {repo_name}: {title}")
        
        temp_dir = None
        
        try:
            # Get repository
            repo = self.github.get_repo(repo_name)
            
            # Check if we have write access, if not, need to fork
            try:
                repo.create_git_ref(
                    ref=f"refs/heads/test-access-{datetime.now().timestamp()}",
                    sha=repo.get_branch(base_branch).commit.sha
                )
                # Delete the test branch
                repo.get_git_ref(f"heads/test-access-{datetime.now().timestamp()}").delete()
                has_write_access = True
            except GithubException:
                has_write_access = False
            
            # If no write access, fork the repo
            if not has_write_access:
                logger.info(f"No write access to {repo_name}, creating fork")
                fork = self.github.get_user().create_fork(repo)
                repo = fork  # Use the fork for operations
                await asyncio.sleep(5)  # Wait for fork to be ready
            
            # Create temp directory for Git operations
            temp_dir = tempfile.mkdtemp(prefix="helios_git_")
            
            # Clone the repository
            git_repo = Repo.clone_from(
                repo.clone_url.replace("https://", f"https://{self.github_token}@"),
                temp_dir,
                branch=base_branch
            )
            
            # Create new branch
            new_branch = git_repo.create_head(branch_name)
            new_branch.checkout()
            
            # Apply patch
            patch_file = Path(temp_dir) / "patch.diff"
            patch_file.write_text(patch_data)
            
            git_repo.git.apply(str(patch_file))
            
            # Commit changes
            git_repo.git.add(A=True)
            git_repo.index.commit(f"fix: {title}")
            
            # Push to remote
            origin = git_repo.remote(name="origin")
            origin.push(refspec=f"{branch_name}:{branch_name}")
            
            # Create pull request
            pr = repo.create_pull(
                title=title,
                body=body,
                head=branch_name if has_write_access else f"{repo.owner.login}:{branch_name}",
                base=base_branch
            )
            
            logger.info(f"Created PR #{pr.number}: {pr.html_url}")
            
            return {
                "success": True,
                "pr_number": pr.number,
                "pr_url": pr.html_url,
                "branch_name": branch_name,
                "repository": repo_name
            }
        
        except GithubException as e:
            logger.error(f"GitHub error creating PR: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e),
                "repository": repo_name
            }
        
        except Exception as e:
            logger.error(f"Error creating PR: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e),
                "repository": repo_name
            }
        
        finally:
            # Cleanup temp directory
            if temp_dir and Path(temp_dir).exists():
                try:
                    shutil.rmtree(temp_dir)
                except Exception as e:
                    logger.warning(f"Error cleaning up temp dir: {e}")
    
    async def create_branch(
        self,
        repo_name: str,
        branch_name: str,
        source_branch: str = "main"
    ) -> Dict[str, Any]:
        """Create a new branch in a repository"""
        logger.info(f"Creating branch {branch_name} in {repo_name}")
        
        try:
            repo = self.github.get_repo(repo_name)
            
            # Get the source branch
            source = repo.get_branch(source_branch)
            
            # Create new branch
            repo.create_git_ref(
                ref=f"refs/heads/{branch_name}",
                sha=source.commit.sha
            )
            
            return {
                "success": True,
                "branch_name": branch_name,
                "source_branch": source_branch,
                "repository": repo_name
            }
        
        except GithubException as e:
            logger.error(f"Error creating branch: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e),
                "repository": repo_name
            }
    
    async def generate_pr_body(
        self,
        cve_id: str,
        cve_description: str,
        remediation: str,
        test_results: Optional[str] = None
    ) -> Dict[str, Any]:
        """Generate a professional PR description for a security patch"""
        logger.info(f"Generating PR body for {cve_id}")
        
        # Create professional PR template
        pr_body = f"""## 🔒 Security Patch: {cve_id}

### Summary
This PR addresses a security vulnerability identified in {cve_id}.

### Vulnerability Details
{cve_description}

### Remediation
{remediation}

### Testing
"""
        
        if test_results:
            pr_body += f"""✅ **All tests passed in sandboxed environment**

<details>
<summary>Test Results</summary>

```
{test_results}
```

</details>
"""
        else:
            pr_body += "⚠️ Please review and test this patch before merging.\n"
        
        pr_body += f"""
### References
- [{cve_id}](https://nvd.nist.gov/vuln/detail/{cve_id})

### Automated Patch
This pull request was automatically generated by **Helios**, an autonomous DevSecOps agent.

---
*Generated on {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC*
"""
        
        return {
            "pr_body": pr_body,
            "cve_id": cve_id
        }
    
    async def fork_repository(self, repo_name: str) -> Dict[str, Any]:
        """Fork a repository to the authenticated user's account"""
        logger.info(f"Forking repository {repo_name}")
        
        try:
            repo = self.github.get_repo(repo_name)
            user = self.github.get_user()
            
            # Check if fork already exists
            try:
                existing_fork = user.get_repo(repo.name)
                return {
                    "success": True,
                    "fork_url": existing_fork.html_url,
                    "fork_name": existing_fork.full_name,
                    "already_existed": True
                }
            except GithubException:
                pass
            
            # Create fork
            fork = user.create_fork(repo)
            
            return {
                "success": True,
                "fork_url": fork.html_url,
                "fork_name": fork.full_name,
                "already_existed": False
            }
        
        except GithubException as e:
            logger.error(f"Error forking repository: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e),
                "repository": repo_name
            }
