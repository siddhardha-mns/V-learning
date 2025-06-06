import streamlit as st
import json
import os
from datetime import datetime
import hashlib
from supabase import create_client, Client
import requests
from urllib.parse import urlencode

# --- Streamlit Secrets Configuration ---
try:
    # Production: Use Streamlit secrets
    SUPABASE_URL = st.secrets["supabase"]["url"]
    SUPABASE_KEY = st.secrets["supabase"]["anon_key"]
    SUPABASE_SERVICE_KEY = st.secrets["supabase"]["service_role_key"]
    ADMIN_PASSWORD = st.secrets.get("admin", {}).get("password", "admin123")
    
    # GitLab OAuth credentials
    GITLAB_CLIENT_ID = st.secrets["gitlab"]["client_id"]
    GITLAB_CLIENT_SECRET = st.secrets["gitlab"]["client_secret"]
    GITLAB_REDIRECT_URI = st.secrets["gitlab"]["redirect_uri"]
    
except Exception as e:
    # Local development fallback
    st.warning("⚠️ Streamlit secrets not found. Using environment variables for local development.")
    SUPABASE_URL = os.getenv("SUPABASE_URL", "your_supabase_url")
    SUPABASE_KEY = os.getenv("SUPABASE_ANON_KEY", "your_anon_key")
    SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY", "your_service_key")
    ADMIN_PASSWORD = "admin123"
    
    # GitLab OAuth credentials
    GITLAB_CLIENT_ID = os.getenv("GITLAB_CLIENT_ID", "your_gitlab_client_id")
    GITLAB_CLIENT_SECRET = os.getenv("GITLAB_CLIENT_SECRET", "your_gitlab_client_secret")
    GITLAB_REDIRECT_URI = os.getenv("GITLAB_REDIRECT_URI", "http://localhost:8501")

# Initialize Supabase client
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
supabase_admin: Client = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)

# Page configuration
st.set_page_config(
    page_title="V-Learn",
    page_icon="📚",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- Authentication Functions ---
def login_with_gitlab():
    """Redirect to GitLab for authentication"""
    gitlab_auth_url = "https://code.swecha.org/oauth/authorize"
    params = {
        "client_id": GITLAB_CLIENT_ID,
        "redirect_uri": GITLAB_REDIRECT_URI,
        "response_type": "code",
        "scope": "read_user"
    }
    st.query_params.clear()  # Clear any existing query params
    st.markdown(f"[Login with GitLab]({gitlab_auth_url}?{urlencode(params)})")

def handle_gitlab_callback():
    """Handle the callback from GitLab after authentication"""
    code = st.query_params.get("code", [None])[0]
    if code:
        token_url = "https://code.swecha.org/oauth/token"
        token_data = {
            "client_id": GITLAB_CLIENT_ID,
            "client_secret": GITLAB_CLIENT_SECRET,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": GITLAB_REDIRECT_URI
        }
        response = requests.post(token_url, data=token_data)
        if response.status_code == 200:
            token_info = response.json()
            access_token = token_info.get("access_token")
            user_info = get_gitlab_user_info(access_token)
            if user_info:
                st.session_state.authenticated = True
                st.session_state.current_user = user_info
                st.success("✅ Login successful!")
                st.query_params.clear()  # Clear query params
                st.experimental_rerun()
        else:
            st.error("❌ Failed to authenticate with GitLab")

def get_gitlab_user_info(access_token):
    """Get user information from GitLab using the access token"""
    user_url = "https://code.swecha.org/api/v4/user"
    headers = {
        "Authorization": f"Bearer {access_token}"
    }
    response = requests.get(user_url, headers=headers)
    if response.status_code == 200:
        return response.json()
    return None

# --- Supabase Database Manager ---
class SupabaseManager:
    def __init__(self):
        self.client = supabase
        self.admin_client = supabase_admin
        self.init_database()
    
    def init_database(self):
        """Initialize Supabase tables (this should be done via Supabase SQL editor)"""
        # This is for reference - you should create these tables in Supabase SQL editor
        create_tables_sql = """
        -- Resources table
        CREATE TABLE IF NOT EXISTS resources (
            id SERIAL PRIMARY KEY,
            title TEXT NOT NULL,
            author TEXT NOT NULL,
            category TEXT NOT NULL,
            description TEXT,
            file_url TEXT,
            external_url TEXT,
            file_type TEXT,
            resource_type TEXT,
            file_size BIGINT,
            timestamp TIMESTAMPTZ DEFAULT NOW(),
            tags TEXT,
            downloads INTEGER DEFAULT 0,
            likes INTEGER DEFAULT 0,
            created_at TIMESTAMPTZ DEFAULT NOW()
        );

        -- Projects table
        CREATE TABLE IF NOT EXISTS projects (
            id SERIAL PRIMARY KEY,
            title TEXT NOT NULL,
            author TEXT NOT NULL,
            category TEXT NOT NULL,
            description TEXT,
            technologies TEXT,
            github_url TEXT,
            demo_url TEXT,
            image_url TEXT,
            timestamp TIMESTAMPTZ DEFAULT NOW(),
            likes INTEGER DEFAULT 0,
            views INTEGER DEFAULT 0,
            created_at TIMESTAMPTZ DEFAULT NOW()
        );

        -- User data table
        CREATE TABLE IF NOT EXISTS user_data (
            id SERIAL PRIMARY KEY,
            user_id TEXT UNIQUE,
            bookmarks JSONB,
            completed JSONB,
            preferences JSONB,
            created_at TIMESTAMPTZ DEFAULT NOW()
        );

        -- Analytics table
        CREATE TABLE IF NOT EXISTS analytics (
            id SERIAL PRIMARY KEY,
            event_type TEXT,
            resource_id INTEGER,
            user_session TEXT,
            timestamp TIMESTAMPTZ DEFAULT NOW(),
            metadata JSONB
        );

        -- Enable Row Level Security
        ALTER TABLE resources ENABLE ROW LEVEL SECURITY;
        ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
        ALTER TABLE user_data ENABLE ROW LEVEL SECURITY;
        ALTER TABLE analytics ENABLE ROW LEVEL SECURITY;

        -- Create policies for public read access
        CREATE POLICY "Public read access for resources" ON resources FOR SELECT USING (true);
        CREATE POLICY "Public read access for projects" ON projects FOR SELECT USING (true);
        CREATE POLICY "Public insert access for resources" ON resources FOR INSERT WITH CHECK (true);
        CREATE POLICY "Public insert access for projects" ON projects FOR INSERT WITH CHECK (true);
        """
        # Note: Execute this SQL in your Supabase SQL editor
        pass
    
    def add_resource(self, resource_data):
        """Add a new resource to the database"""
        try:
            result = self.client.table("resources").insert(resource_data).execute()
            if result.data:
                return result.data[0]['id']
            return None
        except Exception as e:
            st.error(f"Error adding resource: {str(e)}")
            return None
    
    def get_resources(self, limit=None):
        """Get resources from the database"""
        try:
            query = self.client.table("resources").select("*").order("timestamp", desc=True)
            if limit:
                query = query.limit(limit)
            result = query.execute()
            return result.data
        except Exception as e:
            st.error(f"Error fetching resources: {str(e)}")
            return []
    
    def add_project(self, project_data):
        """Add a new project to the database"""
        try:
            result = self.client.table("projects").insert(project_data).execute()
            if result.data:
                return result.data[0]['id']
            return None
        except Exception as e:
            st.error(f"Error adding project: {str(e)}")
            return None
    
    def get_projects(self, limit=None):
        """Get projects from the database"""
        try:
            query = self.client.table("projects").select("*").order("timestamp", desc=True)
            if limit:
                query = query.limit(limit)
            result = query.execute()
            return result.data
        except Exception as e:
            st.error(f"Error fetching projects: {str(e)}")
            return []
    
    def search_resources(self, query_text):
        """Search resources"""
        try:
            result = self.client.table("resources").select("*").or_(
                f"title.ilike.%{query_text}%,author.ilike.%{query_text}%,category.ilike.%{query_text}%,description.ilike.%{query_text}%"
            ).order("timestamp", desc=True).execute()
            return result.data
        except Exception as e:
            st.error(f"Error searching resources: {str(e)}")
            return []
    
    def delete_resource(self, resource_id):
        """Delete a resource"""
        try:
            # First get the resource to check for file URL
            resource = self.client.table("resources").select("file_url").eq("id", resource_id).execute()
            
            # Delete from storage if file exists
            if resource.data and resource.data[0].get('file_url'):
                file_path = self.extract_file_path_from_url(resource.data[0]['file_url'])
                if file_path:
                    self.delete_file_from_storage(file_path)
            
            # Delete from database
            result = self.client.table("resources").delete().eq("id", resource_id).execute()
            return True
        except Exception as e:
            st.error(f"Error deleting resource: {str(e)}")
            return False
    
    def delete_project(self, project_id):
        """Delete a project"""
        try:
            # First get the project to check for image URL
            project = self.client.table("projects").select("image_url").eq("id", project_id).execute()
            
            # Delete from storage if image exists
            if project.data and project.data[0].get('image_url'):
                file_path = self.extract_file_path_from_url(project.data[0]['image_url'])
                if file_path:
                    self.delete_file_from_storage(file_path)
            
            # Delete from database
            result = self.client.table("projects").delete().eq("id", project_id).execute()
            return True
        except Exception as e:
            st.error(f"Error deleting project: {str(e)}")
            return False
    
    def get_stats(self):
        """Get platform statistics"""
        try:
            # Get resource count
            resources_result = self.client.table("resources").select("id", count="exact").execute()
            total_resources = resources_result.count or 0
            
            # Get project count
            projects_result = self.client.table("projects").select("id", count="exact").execute()
            total_projects = projects_result.count or 0
            
            # Get total downloads
            downloads_result = self.client.table("resources").select("downloads").execute()
            total_downloads = sum(r.get('downloads', 0) for r in downloads_result.data) if downloads_result.data else 0
            
            # Get total likes (resources + projects)
            resource_likes_result = self.client.table("resources").select("likes").execute()
            resource_likes = sum(r.get('likes', 0) for r in resource_likes_result.data) if resource_likes_result.data else 0
            
            project_likes_result = self.client.table("projects").select("likes").execute()
            project_likes = sum(p.get('likes', 0) for p in project_likes_result.data) if project_likes_result.data else 0
            
            return {
                'total_resources': total_resources,
                'total_projects': total_projects,
                'total_downloads': total_downloads,
                'total_likes': resource_likes + project_likes
            }
        except Exception as e:
            st.error(f"Error fetching stats: {str(e)}")
            return {
                'total_resources': 0,
                'total_projects': 0,
                'total_downloads': 0,
                'total_likes': 0
            }
    
    def extract_file_path_from_url(self, url):
        """Extract file path from Supabase storage URL"""
        try:
            # Supabase storage URLs format: https://xxx.supabase.co/storage/v1/object/public/bucket/path
            if "/storage/v1/object/public/" in url:
                return url.split("/storage/v1/object/public/")[1]
            return None
        except:
            return None
    
    def delete_file_from_storage(self, file_path):
        """Delete file from Supabase storage"""
        try:
            bucket_name, file_path_in_bucket = file_path.split("/", 1)
            result = self.admin_client.storage.from_(bucket_name).remove([file_path_in_bucket])
            return True
        except Exception as e:
            st.error(f"Error deleting file from storage: {str(e)}")
            return False

# Initialize database manager
db_manager = SupabaseManager()

# --- Utility Functions ---
def get_resource_icon(resource):
    """Get appropriate icon for resource type"""
    file_type = resource.get('file_type', '').lower()
    resource_type = resource.get('resource_type', '').lower()
    
    if resource_type == 'image' or file_type in ['jpg', 'jpeg', 'png', 'gif', 'svg']:
        return "🖼️"
    elif file_type in ['pdf']:
        return "📄"
    elif file_type in ['doc', 'docx']:
        return "📝"
    elif file_type in ['xls', 'xlsx']:
        return "📊"
    elif file_type in ['ppt', 'pptx']:
        return "📈"
    elif file_type in ['zip', 'rar', '7z']:
        return "📦"
    elif file_type in ['mp4', 'avi', 'mov', 'mkv']:
        return "📹"
    elif file_type in ['mp3', 'wav', 'flac']:
        return "🎵"
    elif resource.get('external_url') and not resource.get('file_url'):
        return "🔗"
    else:
        return "📄"

def format_timestamp(timestamp):
    """Format timestamp to readable format"""
    if not timestamp:
        return "Unknown"
    try:
        if isinstance(timestamp, str):
            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        else:
            dt = timestamp
        return dt.strftime("%Y-%m-%d %H:%M")
    except:
        return str(timestamp)

def format_file_size(size_bytes):
    """Format file size to human readable format"""
    if not size_bytes:
        return "Unknown"
    try:
        size_bytes = int(size_bytes)
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024**2:
            return f"{size_bytes/1024:.1f} KB"
        elif size_bytes < 1024**3:
            return f"{size_bytes/(1024**2):.1f} MB"
        else:
            return f"{size_bytes/(1024**3):.1f} GB"
    except:
        return "Unknown"

# --- Main App Pages ---
def main_page():
    st.title("📚 V-Learn: Learning Resources on the Go")
    st.markdown("*Your community-driven learning platform*")
    st.markdown("---")
    
    # Welcome section
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.subheader("📖 Documentation Hub")
        st.write("Access curated documentation for popular tools and technologies.")
        if st.button("Browse Documentation", use_container_width=True):
            st.session_state.current_page = "documentation"
    
    with col2:
        st.subheader("📁 Resource Library")
        st.write("Upload, share, and discover learning resources from the community.")
        if st.button("Explore Resources", use_container_width=True):
            st.session_state.current_page = "resources"
    
    with col3:
        st.subheader("🚀 Project Showcase")
        st.write("Showcase your projects and discover what others have built.")
        if st.button("View Projects", use_container_width=True):
            st.session_state.current_page = "projects"
    
    st.markdown("---")
    
    # Platform statistics
    st.subheader("📊 Platform Statistics")
    stats = db_manager.get_stats()
    
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("📚 Total Resources", stats['total_resources'])
    with col2:
        st.metric("🚀 Projects Showcased", stats['total_projects'])
    with col3:
        st.metric("📥 Downloads", stats['total_downloads'])
    with col4:
        st.metric("❤️ Total Likes", stats['total_likes'])
    
    # Recent activity
    st.markdown("---")
    st.subheader("📈 Recent Activity")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.write("**🆕 Latest Resources:**")
        recent_resources = db_manager.get_resources(limit=3)
        if recent_resources:
            for resource in recent_resources:
                icon = get_resource_icon(resource)
                with st.container():
                    st.write(f"{icon} **{resource['title']}** - {resource['category']}")
                    st.caption(f"By {resource['author']} | {format_timestamp(resource.get('timestamp', ''))}")
                    
                    # Show appropriate link
                    if resource.get('file_url'):
                        st.markdown(f"[📁 View File]({resource['file_url']})")
                    if resource.get('external_url'):
                        st.markdown(f"[🔗 External Link]({resource['external_url']})")
        else:
            st.info("No resources uploaded yet. Be the first to share!")
    
    with col2:
        st.write("**🆕 Latest Projects:**")
        recent_projects = db_manager.get_projects(limit=3)
        if recent_projects:
            for project in recent_projects:
                with st.container():
                    st.write(f"• **{project['title']}** - {project['category']}")
                    st.caption(f"By {project['author']} | {format_timestamp(project.get('timestamp', ''))}")
                    if project.get('demo_url'):
                        st.markdown(f"[🌐 Live Demo]({project['demo_url']})")
        else:
            st.info("No projects showcased yet. Share your work!")

def resource_library_page():
    st.title("📁 Resource Library")
    
    # Tabs for different actions
    tab1, tab2, tab3 = st.tabs(["📚 Browse Resources", "📤 Upload Resource", "🔍 Search"])
    
    with tab1:
        st.subheader("Available Resources")
        resources = db_manager.get_resources()
        
        if resources:
            # Filter options
            col1, col2 = st.columns(2)
            with col1:
                categories = list(set([r['category'] for r in resources]))
                selected_category = st.selectbox("Filter by Category", ["All"] + categories)
            with col2:
                sort_by = st.selectbox("Sort by", ["Newest", "Most Downloads", "Most Likes"])
            
            # Apply filters
            filtered_resources = resources
            if selected_category != "All":
                filtered_resources = [r for r in resources if r['category'] == selected_category]
            
            # Sort resources
            if sort_by == "Most Downloads":
                filtered_resources.sort(key=lambda x: x.get('downloads', 0), reverse=True)
            elif sort_by == "Most Likes":
                filtered_resources.sort(key=lambda x: x.get('likes', 0), reverse=True)
            
            # Display resources
            for resource in filtered_resources:
                icon = get_resource_icon(resource)
                with st.expander(f"{icon} {resource['title']} - {resource['category']}"):
                    col1, col2 = st.columns([2, 1])
                    with col1:
                        st.write(f"**Author:** {resource['author']}")
                        st.write(f"**Description:** {resource.get('description', 'No description')}")
                        st.write(f"**Category:** {resource['category']}")
                        st.write(f"**Uploaded:** {format_timestamp(resource.get('timestamp', 'Unknown'))}")
                        st.write(f"**Downloads:** {resource.get('downloads', 0)} | **Likes:** {resource.get('likes', 0)}")
                        
                        # Show both file and external links if available
                        links_col1, links_col2 = st.columns(2)
                        with links_col1:
                            if resource.get('file_url'):
                                st.markdown(f"[📁 Download File]({resource['file_url']})")
                        with links_col2:
                            if resource.get('external_url'):
                                st.markdown(f"[🔗 External Link]({resource['external_url']})")
                    
                    with col2:
                        if resource.get('resource_type') == 'image' and resource.get('file_url'):
                            try:
                                st.image(resource['file_url'], width=200)
                            except:
                                st.write("📷 Image preview unavailable")
                        elif resource.get('external_url') and not resource.get('file_url'):
                            st.write("🔗 External Resource")
                        
                        # Admin controls
                        if st.session_state.get('is_admin', False):
                            if st.button(f"🗑️ Delete", key=f"del_res_{resource['id']}"):
                                if db_manager.delete_resource(resource['id']):
                                    st.success("Resource deleted!")
                                    st.experimental_rerun()
        else:
            st.info("📭 No resources available yet. Upload the first one!")
    
    with tab2:
        st.subheader("📤 Upload New Resource")
        
        with st.form("upload_resource"):
            col1, col2 = st.columns(2)
            
            with col1:
                title = st.text_input("Resource Title *", placeholder="e.g., Python Cheat Sheet")
                author = st.text_input("Author Name *", placeholder="Your name")
                category = st.selectbox("Category *", [
                    "Programming", "Data Science", "Web Development", "Mobile Development",
                    "DevOps", "Design", "Documentation", "Tutorial", "Cheat Sheet", "Other"
                ])
            
            with col2:
                description = st.text_area("Description", placeholder="Brief description of the resource")
                tags = st.text_input("Tags", placeholder="python, tutorial, beginner (comma-separated)")
            
            st.markdown("**Choose upload method:**")
            upload_method = st.radio("", ["📁 Upload File", "🔗 External Link", "📁 Both File and Link"])
            
            file_url = None
            external_url = None
            file_type = None
            resource_type = None
            file_size = None
            
            if upload_method in ["📁 Upload File", "📁 Both File and Link"]:
                uploaded_file = st.file_uploader(
                    "Choose a file",
                    type=['pdf', 'doc', 'docx', 'ppt', 'pptx', 'xls', 'xlsx', 'txt', 'md', 
                          'png', 'jpg', 'jpeg', 'gif', 'svg', 'mp4', 'avi', 'mov', 'zip', 'rar'],
                    help="Supported formats: Documents, Images, Videos, Archives"
                )
                
                if uploaded_file:
                    # Upload to Supabase Storage
                    try:
                        # Generate unique filename
                        file_extension = uploaded_file.name.split('.')[-1].lower()
                        unique_filename = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{hashlib.md5(uploaded_file.name.encode()).hexdigest()[:8]}.{file_extension}"
                        
                        # Upload file
                        bucket_name = "resources"  # Make sure this bucket exists in your Supabase storage
                        file_path = f"uploads/{unique_filename}"
                        
                        # Upload file to Supabase storage
                        file_bytes = uploaded_file.read()
                        upload_result = supabase.storage.from_(bucket_name).upload(file_path, file_bytes)
                        
                        if upload_result:
                            # Get public URL
                            file_url = supabase.storage.from_(bucket_name).get_public_url(file_path)
                            file_type = file_extension
                            file_size = len(file_bytes)
                            
                            # Determine resource type
                            if file_extension in ['jpg', 'jpeg', 'png', 'gif', 'svg']:
                                resource_type = 'image'
                            elif file_extension in ['mp4', 'avi', 'mov', 'mkv']:
                                resource_type = 'video'
                            elif file_extension in ['mp3', 'wav', 'flac']:
                                resource_type = 'audio'
                            else:
                                resource_type = 'document'
                            
                            st.success(f"✅ File uploaded successfully! Size: {format_file_size(file_size)}")
                    except Exception as e:
                        st.error(f"❌ Error uploading file: {str(e)}")
            
            if upload_method in ["🔗 External Link", "📁 Both File and Link"]:
                external_url = st.text_input("External URL", placeholder="https://example.com/resource")
                if external_url and not external_url.startswith(('http://', 'https://')):
                    st.warning("⚠️ Please include http:// or https:// in the URL")
                    external_url = None
            
            submitted = st.form_submit_button("📤 Upload Resource", use_container_width=True)
            
            if submitted:
                # Validation
                if not title or not author or not category:
                    st.error("❌ Please fill in all required fields marked with *")
                elif not file_url and not external_url:
                    st.error("❌ Please provide either a file upload or external URL")
                else:
                    # Prepare resource data
                    resource_data = {
                        "title": title,
                        "author": author,
                        "category": category,
                        "description": description,
                        "file_url": file_url,
                        "external_url": external_url,
                        "file_type": file_type,
                        "resource_type": resource_type,
                        "file_size": file_size,
                        "tags": tags,
                        "timestamp": datetime.now().isoformat(),
                        "downloads": 0,
                        "likes": 0
                    }
                    
                    # Add to database
                    resource_id = db_manager.add_resource(resource_data)
                    if resource_id:
                        st.success(f"🎉 Resource '{title}' uploaded successfully!")
                        st.balloons()
                        st.info("Your resource is now available in the library!")
                    else:
                        st.error("❌ Failed to upload resource. Please try again.")
    
    with tab3:
        st.subheader("🔍 Search Resources")
        
        search_query = st.text_input("Search resources...", placeholder="Enter keywords")
        
        if search_query:
            search_results = db_manager.search_resources(search_query)
            
            if search_results:
                st.success(f"Found {len(search_results)} result(s)")
                
                for resource in search_results:
                    icon = get_resource_icon(resource)
                    with st.expander(f"{icon} {resource['title']} - {resource['category']}"):
                        col1, col2 = st.columns([2, 1])
                        with col1:
                            st.write(f"**Author:** {resource['author']}")
                            st.write(f"**Description:** {resource.get('description', 'No description')}")
                            st.write(f"**Category:** {resource['category']}")
                            st.write(f"**Uploaded:** {format_timestamp(resource.get('timestamp', 'Unknown'))}")
                            
                            # Show both file and external links if available
                            links_col1, links_col2 = st.columns(2)
                            with links_col1:
                                if resource.get('file_url'):
                                    st.markdown(f"[📁 Download File]({resource['file_url']})")
                            with links_col2:
                                if resource.get('external_url'):
                                    st.markdown(f"[🔗 External Link]({resource['external_url']})")
                        
                        with col2:
                            if resource.get('resource_type') == 'image' and resource.get('file_url'):
                                try:
                                    st.image(resource['file_url'], width=200)
                                except:
                                    st.write("📷 Image preview unavailable")
            else:
                st.info("No resources found matching your search.")

def project_showcase_page():
    st.title("🚀 Project Showcase")
    
    # Tabs for different actions
    tab1, tab2 = st.tabs(["🌟 Browse Projects", "➕ Add Project"])
    
    with tab1:
        st.subheader("Featured Projects")
        projects = db_manager.get_projects()
        
        if projects:
            # Filter options
            col1, col2 = st.columns(2)
            with col1:
                categories = list(set([p['category'] for p in projects]))
                selected_category = st.selectbox("Filter by Category", ["All"] + categories)
            with col2:
                sort_by = st.selectbox("Sort by", ["Newest", "Most Likes", "Most Views"])
            
            # Apply filters
            filtered_projects = projects
            if selected_category != "All":
                filtered_projects = [p for p in projects if p['category'] == selected_category]
            
            # Sort projects
            if sort_by == "Most Likes":
                filtered_projects.sort(key=lambda x: x.get('likes', 0), reverse=True)
            elif sort_by == "Most Views":
                filtered_projects.sort(key=lambda x: x.get('views', 0), reverse=True)
            
            # Display projects in grid
            cols = st.columns(2)
            for idx, project in enumerate(filtered_projects):
                with cols[idx % 2]:
                    with st.container():
                        st.markdown(f"### 🚀 {project['title']}")
                        st.write(f"**Category:** {project['category']}")
                        st.write(f"**Author:** {project['author']}")
                        st.write(f"**Description:** {project.get('description', 'No description')}")
                        
                        if project.get('technologies'):
                            st.write(f"**Technologies:** {project['technologies']}")
                        
                        # Display project image if available
                        if project.get('image_url'):
                            try:
                                st.image(project['image_url'], width=300)
                            except:
                                st.write("🖼️ Image preview unavailable")
                        
                        # Project stats
                        col1, col2, col3 = st.columns(3)
                        with col1:
                            st.metric("❤️ Likes", project.get('likes', 0))
                        with col2:
                            st.metric("👀 Views", project.get('views', 0))
                        with col3:
                            st.write(f"📅 {format_timestamp(project.get('timestamp', ''))}")
                        
                        # Project links
                        links_col1, links_col2 = st.columns(2)
                        with links_col1:
                            if project.get('github_url'):
                                st.markdown(f"[📱 GitHub]({project['github_url']})")
                        with links_col2:
                            if project.get('demo_url'):
                                st.markdown(f"[🌐 Live Demo]({project['demo_url']})")
                        
                        # Admin controls
                        if st.session_state.get('is_admin', False):
                            if st.button(f"🗑️ Delete", key=f"del_proj_{project['id']}"):
                                if db_manager.delete_project(project['id']):
                                    st.success("Project deleted!")
                                    st.experimental_rerun()
                        
                        st.markdown("---")
        else:
            st.info("📭 No projects showcased yet. Be the first to share your work!")
    
    with tab2:
        st.subheader("➕ Add Your Project")
        
        with st.form("add_project"):
            col1, col2 = st.columns(2)
            
            with col1:
                title = st.text_input("Project Title *", placeholder="e.g., Todo App with React")
                author = st.text_input("Author Name *", placeholder="Your name")
                category = st.selectbox("Category *", [
                    "Web Development", "Mobile Development", "Data Science", "Machine Learning",
                    "Game Development", "Desktop Application", "API/Backend", "DevOps", "Other"
                ])
                technologies = st.text_input("Technologies Used", placeholder="React, Node.js, MongoDB")
            
            with col2:
                description = st.text_area("Project Description *", placeholder="Describe what your project does")
                github_url = st.text_input("GitHub Repository URL", placeholder="https://github.com/username/repo")
                demo_url = st.text_input("Live Demo URL", placeholder="https://yourproject.com")
            
            # Project image upload
            st.markdown("**Project Screenshot/Image (Optional):**")
            uploaded_image = st.file_uploader(
                "Upload project image",
                type=['png', 'jpg', 'jpeg', 'gif'],
                help="Upload a screenshot or image of your project"
            )
            
            image_url = None
            if uploaded_image:
                try:
                    # Generate unique filename
                    file_extension = uploaded_image.name.split('.')[-1].lower()
                    unique_filename = f"project_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{hashlib.md5(uploaded_image.name.encode()).hexdigest()[:8]}.{file_extension}"
                    
                    # Upload to Supabase storage
                    bucket_name = "projects"  # Make sure this bucket exists
                    file_path = f"images/{unique_filename}"
                    
                    file_bytes = uploaded_image.read()
                    upload_result = supabase.storage.from_(bucket_name).upload(file_path, file_bytes)
                    
                    if upload_result:
                        image_url = supabase.storage.from_(bucket_name).get_public_url(file_path)
                        st.success("✅ Image uploaded successfully!")
                        st.image(image_url, width=300)
                except Exception as e:
                    st.error(f"❌ Error uploading image: {str(e)}")
            
            submitted = st.form_submit_button("🚀 Add Project", use_container_width=True)
            
            if submitted:
                # Validation
                if not title or not author or not category or not description:
                    st.error("❌ Please fill in all required fields marked with *")
                elif github_url and not github_url.startswith(('http://', 'https://')):
                    st.error("❌ GitHub URL must start with http:// or https://")
                elif demo_url and not demo_url.startswith(('http://', 'https://')):
                    st.error("❌ Demo URL must start with http:// or https://")
                else:
                    # Prepare project data
                    project_data = {
                        "title": title,
                        "author": author,
                        "category": category,
                        "description": description,
                        "technologies": technologies,
                        "github_url": github_url if github_url else None,
                        "demo_url": demo_url if demo_url else None,
                        "image_url": image_url,
                        "timestamp": datetime.now().isoformat(),
                        "likes": 0,
                        "views": 0
                    }
                    
                    # Add to database
                    project_id = db_manager.add_project(project_data)
                    if project_id:
                        st.success(f"🎉 Project '{title}' added successfully!")
                        st.balloons()
                        st.info("Your project is now live in the showcase!")
                    else:
                        st.error("❌ Failed to add project. Please try again.")

def documentation_page():
    st.title("📖 Documentation Hub")
    st.markdown("*Curated documentation and guides for popular tools and technologies*")
    
    # Documentation categories
    doc_categories = {
        "🐍 Python": {
            "Official Python Docs": "https://docs.python.org/3/",
            "Django Documentation": "https://docs.djangoproject.com/",
            "Flask Documentation": "https://flask.palletsprojects.com/",
            "FastAPI Documentation": "https://fastapi.tiangolo.com/",
            "Pandas Documentation": "https://pandas.pydata.org/docs/",
            "NumPy Documentation": "https://numpy.org/doc/",
            "Matplotlib Documentation": "https://matplotlib.org/stable/contents.html"
        },
        "🌐 Web Development": {
            "MDN Web Docs": "https://developer.mozilla.org/",
            "React Documentation": "https://react.dev/",
            "Vue.js Documentation": "https://vuejs.org/guide/",
            "Angular Documentation": "https://angular.io/docs",
            "Node.js Documentation": "https://nodejs.org/docs/",
            "Express.js Documentation": "https://expressjs.com/",
            "Bootstrap Documentation": "https://getbootstrap.com/docs/"
        },
        "🗄️ Databases": {
            "PostgreSQL Documentation": "https://www.postgresql.org/docs/",
            "MySQL Documentation": "https://dev.mysql.com/doc/",
            "MongoDB Documentation": "https://docs.mongodb.com/",
            "Redis Documentation": "https://redis.io/documentation",
            "SQLite Documentation": "https://sqlite.org/docs.html"
        },
        "☁️ Cloud & DevOps": {
            "AWS Documentation": "https://docs.aws.amazon.com/",
            "Google Cloud Documentation": "https://cloud.google.com/docs",
            "Azure Documentation": "https://docs.microsoft.com/azure/",
            "Docker Documentation": "https://docs.docker.com/",
            "Kubernetes Documentation": "https://kubernetes.io/docs/",
            "Git Documentation": "https://git-scm.com/doc"
        },
        "📱 Mobile Development": {
            "Flutter Documentation": "https://docs.flutter.dev/",
            "React Native Documentation": "https://reactnative.dev/docs/getting-started",
            "Android Developer Docs": "https://developer.android.com/docs",
            "iOS Developer Documentation": "https://developer.apple.com/documentation/"
        },
        "🤖 AI/ML": {
            "TensorFlow Documentation": "https://www.tensorflow.org/guide",
            "PyTorch Documentation": "https://pytorch.org/docs/",
            "Scikit-learn Documentation": "https://scikit-learn.org/stable/",
            "Hugging Face Documentation": "https://huggingface.co/docs",
            "OpenAI API Documentation": "https://platform.openai.com/docs"
        }
    }
    
    # Display documentation categories
    for category, docs in doc_categories.items():
        with st.expander(f"{category}", expanded=False):
            for doc_name, doc_url in docs.items():
                col1, col2 = st.columns([3, 1])
                with col1:
                    st.write(f"📚 **{doc_name}**")
                with col2:
                    st.markdown(f"[🔗 Open]({doc_url})")
    
    st.markdown("---")
    
    # Quick links section
    st.subheader("🔗 Quick Links")
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("**🛠️ Development Tools**")
        st.markdown("- [Visual Studio Code](https://code.visualstudio.com/docs)")
        st.markdown("- [GitHub](https://docs.github.com/)")
        st.markdown("- [Stack Overflow](https://stackoverflow.com/)")
        st.markdown("- [CodePen](https://codepen.io/)")
    
    with col2:
        st.markdown("**📖 Learning Resources**")
        st.markdown("- [freeCodeCamp](https://www.freecodecamp.org/)")
        st.markdown("- [Codecademy](https://www.codecademy.com/)")
        st.markdown("- [MDN Learning](https://developer.mozilla.org/en-US/docs/Learn)")
        st.markdown("- [W3Schools](https://www.w3schools.com/)")
    
    with col3:
        st.markdown("**🎯 Practice Platforms**")
        st.markdown("- [LeetCode](https://leetcode.com/)")
        st.markdown("- [HackerRank](https://www.hackerrank.com/)")
        st.markdown("- [Codewars](https://www.codewars.com/)")
        st.markdown("- [Project Euler](https://projecteuler.net/)")

def admin_page():
    st.title("🛠️ Admin Panel")
    
    if not st.session_state.get('is_admin', False):
        st.error("❌ Access denied. Admin privileges required.")
        return
    
    # Admin dashboard
    st.subheader("📊 Platform Overview")
    stats = db_manager.get_stats()
    
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("📚 Total Resources", stats['total_resources'])
    with col2:
        st.metric("🚀 Total Projects", stats['total_projects'])
    with col3:
        st.metric("📥 Total Downloads", stats['total_downloads'])
    with col4:
        st.metric("❤️ Total Likes", stats['total_likes'])
    
    st.markdown("---")
    
    # Management tabs
    tab1, tab2, tab3 = st.tabs(["📚 Manage Resources", "🚀 Manage Projects", "⚙️ System Settings"])
    
    with tab1:
        st.subheader("📚 Resource Management")
        resources = db_manager.get_resources()
        
        if resources:
            for resource in resources:
                with st.expander(f"📄 {resource['title']} - {resource['category']}"):
                    col1, col2 = st.columns([2, 1])
                    with col1:
                        st.write(f"**Author:** {resource['author']}")
                        st.write(f"**Description:** {resource.get('description', 'No description')}")
                        st.write(f"**Downloads:** {resource.get('downloads', 0)}")
                        st.write(f"**Likes:** {resource.get('likes', 0)}")
                        st.write(f"**Uploaded:** {format_timestamp(resource.get('timestamp', ''))}")
                        
                        if resource.get('file_url'):
                            st.markdown(f"[📁 File URL]({resource['file_url']})")
                        if resource.get('external_url'):
                            st.markdown(f"[🔗 External URL]({resource['external_url']})")
                    
                    with col2:
                        if st.button(f"🗑️ Delete Resource", key=f"admin_del_res_{resource['id']}"):
                            if db_manager.delete_resource(resource['id']):
                                st.success("Resource deleted!")
                                st.experimental_rerun()
        else:
            st.info("No resources to manage.")
    
    with tab2:
        st.subheader("🚀 Project Management")
        projects = db_manager.get_projects()
        
        if projects:
            for project in projects:
                with st.expander(f"🚀 {project['title']} - {project['category']}"):
                    col1, col2 = st.columns([2, 1])
                    with col1:
                        st.write(f"**Author:** {project['author']}")
                        st.write(f"**Description:** {project.get('description', 'No description')}")
                        st.write(f"**Technologies:** {project.get('technologies', 'Not specified')}")
                        st.write(f"**Likes:** {project.get('likes', 0)}")
                        st.write(f"**Views:** {project.get('views', 0)}")
                        st.write(f"**Added:** {format_timestamp(project.get('timestamp', ''))}")
                        
                        if project.get('github_url'):
                            st.markdown(f"[📱 GitHub]({project['github_url']})")
                        if project.get('demo_url'):
                            st.markdown(f"[🌐 Demo]({project['demo_url']})")
                    
                    with col2:
                        if project.get('image_url'):
                            try:
                                st.image(project['image_url'], width=200)
                            except:
                                st.write("🖼️ Image unavailable")
                        
                        if st.button(f"🗑️ Delete Project", key=f"admin_del_proj_{project['id']}"):
                            if db_manager.delete_project(project['id']):
                                st.success("Project deleted!")
                                st.experimental_rerun()
        else:
            st.info("No projects to manage.")
    
    with tab3:
        st.subheader("⚙️ System Settings")
        
        # Database status
        st.write("**📊 Database Status:**")
        try:
            test_query = db_manager.client.table("resources").select("id").limit(1).execute()
            st.success("✅ Database connection healthy")
        except Exception as e:
            st.error(f"❌ Database connection error: {str(e)}")
        
        # Storage status
        st.write("**💾 Storage Status:**")
        try:
            buckets = supabase.storage.list_buckets()
            st.success(f"✅ Storage accessible - {len(buckets)} buckets")
        except Exception as e:
            st.error(f"❌ Storage connection error: {str(e)}")
        
        # Clear cache
        if st.button("🗑️ Clear Cache"):
            st.cache_data.clear()
            st.success("Cache cleared!")

# --- Main App Logic ---
def main():
    # Initialize session state
    if 'current_page' not in st.session_state:
        st.session_state.current_page = 'home'
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
    if 'is_admin' not in st.session_state:
        st.session_state.is_admin = False
    
    # Handle GitLab OAuth callback
    if st.query_params.get("code"):
        handle_gitlab_callback()
    
    # Sidebar
    with st.sidebar:
        st.title("🎯 Navigation")
        
        # Authentication section
        if not st.session_state.authenticated:
            st.subheader("🔐 Authentication")
            login_with_gitlab()
            
            # Admin login
            with st.expander("🛠️ Admin Access"):
                admin_password = st.text_input("Admin Password", type="password")
                if st.button("Login as Admin"):
                    if admin_password == ADMIN_PASSWORD:
                        st.session_state.is_admin = True
                        st.session_state.authenticated = True
                        st.success("✅ Admin access granted!")
                        st.experimental_rerun()
                    else:
                        st.error("❌ Invalid admin password")
        else:
            st.success(f"✅ Welcome, {st.session_state.get('current_user', {}).get('name', 'Admin')}!")
            if st.button("🚪 Logout"):
                st.session_state.authenticated = False
                st.session_state.is_admin = False
                st.session_state.current_user = None
                st.experimental_rerun()
        
        st.markdown("---")
        
        # Navigation menu
        menu_items = [
            ("🏠 Home", "home"),
            ("📖 Documentation", "documentation"),
            ("📁 Resources", "resources"),
            ("🚀 Projects", "projects")
        ]
        
        if st.session_state.get('is_admin', False):
            menu_items.append(("🛠️ Admin", "admin"))
        
        for label, page in menu_items:
            if st.button(label, use_container_width=True):
                st.session_state.current_page = page
                st.experimental_rerun()
        
        st.markdown("---")
        
        # Quick stats
        st.subheader("📊 Quick Stats")
        stats = db_manager.get_stats()
        st.metric("Resources", stats['total_resources'])
        st.metric("Projects", stats['total_projects'])
        st.metric("Downloads", stats['total_downloads'])
        
        # Footer
        st.markdown("---")
        st.markdown("**V-Learn Platform**")
        st.caption("Community-driven learning resources")
        st.caption("Built with ❤️ using Streamlit")
    
    # Main content area
    if st.session_state.current_page == 'home':
        main_page()
    elif st.session_state.current_page == 'documentation':
        documentation_page()
    elif st.session_state.current_page == 'resources':
        resource_library_page()
    elif st.session_state.current_page == 'projects':
        project_showcase_page()
    elif st.session_state.current_page == 'admin':
        admin_page()

if __name__ == "__main__":
    main()
