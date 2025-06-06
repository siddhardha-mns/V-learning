import streamlit as st
import json
import os
from datetime import datetime
from tempfile import NamedTemporaryFile
import hashlib
import mimetypes
from supabase import create_client, Client
import uuid

# --- Streamlit Secrets Configuration ---
try:
    # Production: Use Streamlit secrets
    SUPABASE_URL = st.secrets["supabase"]["url"]
    SUPABASE_KEY = st.secrets["supabase"]["anon_key"]
    SUPABASE_SERVICE_KEY = st.secrets["supabase"]["service_role_key"]
    ADMIN_PASSWORD = st.secrets.get("admin", {}).get("password", "admin123")
    
except Exception as e:
    # Local development fallback
    st.warning("⚠️ Streamlit secrets not found. Using environment variables for local development.")
    SUPABASE_URL = os.getenv("SUPABASE_URL", "your_supabase_url")
    SUPABASE_KEY = os.getenv("SUPABASE_ANON_KEY", "your_anon_key")
    SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY", "your_service_key")
    ADMIN_PASSWORD = "admin123"

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
def init_session_state():
    """Initialize session state variables"""
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
    if 'current_user' not in st.session_state:
        st.session_state.current_user = None
    if 'current_page' not in st.session_state:
        st.session_state.current_page = 'home'

def require_auth():
    """Check if user is authenticated"""
    return st.session_state.get('authenticated', False)

def get_current_user():
    """Get current user info"""
    return st.session_state.get('current_user', None)

def logout():
    """Logout current user"""
    st.session_state.authenticated = False
    st.session_state.current_user = None
    st.success("✅ Logged out successfully!")
    st.rerun()

def login_page():
    """Display login page"""
    st.title("🔐 V-Learn Login")
    st.markdown("---")
    
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        st.subheader("Welcome to V-Learn")
        st.markdown("Your community-driven learning platform")
        
        # Login form
        with st.form("login_form"):
            username = st.text_input("Username", placeholder="Enter your username")
            password = st.text_input("Password", type="password", placeholder="Enter your password")
            
            col1, col2 = st.columns(2)
            with col1:
                login_btn = st.form_submit_button("🔐 Login", use_container_width=True)
            with col2:
                register_btn = st.form_submit_button("📝 Register", use_container_width=True)
            
            if login_btn:
                if authenticate_user(username, password):
                    st.session_state.authenticated = True
                    st.session_state.current_user = {
                        'username': username,
                        'full_name': username.title()
                    }
                    st.success("✅ Login successful!")
                    st.rerun()
                else:
                    st.error("❌ Invalid username or password")
            
            if register_btn:
                if register_user(username, password):
                    st.success("✅ Registration successful! Please login.")
                else:
                    st.error("❌ Registration failed. Username might already exist.")
        
        st.markdown("---")
        st.markdown("**Demo Credentials:**")
        st.code("Username: demo\nPassword: demo123")

def authenticate_user(username, password):
    """Simple authentication - you can enhance this with proper user management"""
    # Demo user
    if username == "demo" and password == "demo123":
        return True
    
    # Check if user exists in a simple way (you can enhance this with Supabase Auth)
    try:
        # Simple file-based user storage for demo
        users_file = "users.json"
        if os.path.exists(users_file):
            with open(users_file, 'r') as f:
                users = json.load(f)
                user_data = users.get(username)
                if user_data and user_data.get('password') == password:
                    return True
    except:
        pass
    
    return False

def register_user(username, password):
    """Simple user registration"""
    if not username or not password or len(password) < 6:
        return False
    
    try:
        users_file = "users.json"
        users = {}
        
        # Load existing users
        if os.path.exists(users_file):
            with open(users_file, 'r') as f:
                users = json.load(f)
        
        # Check if user already exists
        if username in users:
            return False
        
        # Add new user
        users[username] = {
            'password': password,
            'created_at': datetime.now().isoformat(),
            'full_name': username.title()
        }
        
        # Save users
        with open(users_file, 'w') as f:
            json.dump(users, f, indent=2)
        
        return True
    except:
        return False

# --- Database Manager (keeping the Supabase integration) ---
class SupabaseManager:
    def __init__(self):
        self.client = supabase
        self.admin_client = supabase_admin
    
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
            result = self.client.table("resources").delete().eq("id", resource_id).execute()
            return True
        except Exception as e:
            st.error(f"Error deleting resource: {str(e)}")
            return False
    
    def delete_project(self, project_id):
        """Delete a project"""
        try:
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

# Initialize database manager
db_manager = SupabaseManager()

# --- Supabase Storage Upload Function ---
def upload_to_supabase(uploaded_file, bucket_name="vlearn"):
    """Upload file to Supabase Storage and return URL and metadata"""
    if not uploaded_file:
        return None
    
    try:
        # Generate unique filename
        file_hash = hashlib.md5(uploaded_file.getvalue()).hexdigest()[:10]
        file_extension = uploaded_file.name.split('.')[-1] if '.' in uploaded_file.name else ''
        filename = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{file_hash}.{file_extension}"
        file_path = f"uploads/{filename}"
        
        # Upload to Supabase Storage
        result = supabase_admin.storage.from_(bucket_name).upload(
            file_path, 
            uploaded_file.getvalue(),
            file_options={
                "content-type": uploaded_file.type or "application/octet-stream"
            }
        )
        
        if result:
            # Get public URL
            public_url = supabase_admin.storage.from_(bucket_name).get_public_url(file_path)
            
            # Determine resource type
            resource_type = "image" if uploaded_file.type and uploaded_file.type.startswith("image") else \
                           "video" if uploaded_file.type and uploaded_file.type.startswith("video") else "file"
            
            return {
                "url": public_url,
                "file_path": file_path,
                "resource_type": resource_type,
                "format": file_extension,
                "bytes": len(uploaded_file.getvalue()),
                "created_at": datetime.now().isoformat()
            }
    except Exception as e:
        st.error(f"❌ Upload failed: {str(e)}")
        return None

# --- Admin Authentication ---
def check_admin_password():
    """Simple admin authentication"""
    if 'admin_authenticated' not in st.session_state:
        st.session_state.admin_authenticated = False
    
    if not st.session_state.admin_authenticated:
        st.subheader("🔐 Admin Login")
        password = st.text_input("Enter admin password:", type="password")
        if st.button("Login"):
            if password == ADMIN_PASSWORD:
                st.session_state.admin_authenticated = True
                st.success("✅ Admin authenticated!")
                st.rerun()
            else:
                st.error("❌ Invalid password")
        return False
    return True

# --- Utility Functions ---
def validate_url(url):
    """Simple URL validation"""
    if not url:
        return True
    return url.startswith(('http://', 'https://'))

def get_resource_icon(resource):
    """Get appropriate icon based on resource type"""
    if resource.get('external_url') and not resource.get('file_url'):
        return "🔗"
    elif resource.get('resource_type') == 'image':
        return "🖼️"
    elif resource.get('resource_type') == 'video':
        return "🎥"
    elif resource.get('file_type', '').startswith('application/pdf'):
        return "📄"
    else:
        return "📚"

def format_timestamp(timestamp_str):
    """Format timestamp for display"""
    try:
        if 'T' in timestamp_str:
            # ISO format from Supabase
            dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            return dt.strftime("%Y-%m-%d %H:%M")
        else:
            # Already formatted
            return timestamp_str
    except:
        return timestamp_str

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
        else:
            st.info("No resources available yet. Upload the first one!")
    
    with tab2:
        st.subheader("📤 Upload New Resource")
        
        # Resource type selection
        resource_type_option = st.radio(
            "What type of resource are you sharing?",
            options=["📁 File Upload", "🔗 External Link", "📁🔗 Both File and Link"],
            horizontal=True
        )
        
        with st.form("upload_form"):
            col1, col2 = st.columns(2)
            
            with col1:
                title = st.text_input("Resource Title*", placeholder="e.g., Python Basics Tutorial")
                author = st.text_input("Your Name*", placeholder="e.g., John Doe")
                category = st.selectbox("Category*", [
                    "Programming", "Web Development", "Data Science", "Design", 
                    "Machine Learning", "Mobile Development", "DevOps", "Database",
                    "UI/UX", "Cybersecurity", "Cloud Computing", "Other"
                ])
            
            with col2:
                description = st.text_area("Description", placeholder="Brief description of the resource...")
                tags = st.text_input("Tags (comma-separated)", placeholder="python, tutorial, beginner")
            
            # Conditional inputs based on resource type
            uploaded_file = None
            external_url = ""
            
            if resource_type_option in ["📁 File Upload", "📁🔗 Both File and Link"]:
                uploaded_file = st.file_uploader(
                    "Choose a file (images, videos, PDFs, documents)", 
                    type=["jpg", "jpeg", "png", "gif", "mp4", "mov", "avi", "pdf", "txt", "docx", "pptx", "xlsx", "zip"]
                )
            
            if resource_type_option in ["🔗 External Link", "📁🔗 Both File and Link"]:
                external_url = st.text_input(
                    "External URL", 
                    placeholder="https://example.com/resource",
                    help="Link to external resource (website, article, tutorial, etc.)"
                )
            
            submitted = st.form_submit_button("📤 Upload Resource", use_container_width=True)
            
            # Validation and submission
            if submitted and title and author:
                # Validate inputs based on resource type
                is_valid = True
                error_messages = []
                
                if resource_type_option == "📁 File Upload" and not uploaded_file:
                    error_messages.append("Please upload a file.")
                    is_valid = False
                elif resource_type_option == "🔗 External Link" and not external_url:
                    error_messages.append("Please provide an external URL.")
                    is_valid = False
                elif resource_type_option == "📁🔗 Both File and Link" and not uploaded_file and not external_url:
                    error_messages.append("Please provide either a file or an external URL (or both).")
                    is_valid = False
                
                # Validate URL format
                if external_url and not validate_url(external_url):
                    error_messages.append("Please enter a valid URL (starting with http:// or https://).")
                    is_valid = False
                
                if is_valid:
                    resource_data = {
                        "title": title,
                        "author": author,
                        "category": category,
                        "description": description,
                        "external_url": external_url or None,
                        "tags": tags,
                        "timestamp": datetime.now().isoformat()
                    }
                    
                    # Handle file upload if present
                    if uploaded_file:
                        with st.spinner("🔄 Uploading file to Supabase..."):
                            upload_result = upload_to_supabase(uploaded_file)
                            
                            if upload_result:
                                resource_data.update({
                                    "file_url": upload_result["url"],
                                    "file_type": uploaded_file.type,
                                    "resource_type": upload_result["resource_type"],
                                    "file_size": upload_result["bytes"]
                                })
                            else:
                                st.error("File upload failed. Please try again.")
                                st.stop()
                    
                    # Save to database
                    resource_id = db_manager.add_resource(resource_data)
                    if resource_id:
                        st.success("✅ Resource uploaded successfully!")
                        st.balloons()
                    else:
                        st.error("Failed to save resource. Please try again.")
                else:
                    for error in error_messages:
                        st.error(error)
            elif submitted:
                st.error("Please fill in all required fields.")
    
    with tab3:
        st.subheader("🔍 Search Resources")
        search_term = st.text_input("Search by title, author, category, or description...")
        
        if search_term:
            filtered_resources = db_manager.search_resources(search_term)
            
            st.write(f"Found **{len(filtered_resources)}** results for '{search_term}':")
            
            for resource in filtered_resources:
                icon = get_resource_icon(resource)
                with st.expander(f"{icon} {resource['title']} - {resource['category']}"):
                    col1, col2 = st.columns([3, 1])
                    with col1:
                        st.write(f"**Author:** {resource['author']}")
                        st.write(f"**Description:** {resource.get('description', 'No description')}")
                        st.write(f"**Downloads:** {resource.get('downloads', 0)} | **Likes:** {resource.get('likes', 0)}")
                        
                        # Show both types of links
                        if resource.get('file_url'):
                            st.markdown(f"[📁 View File]({resource['file_url']})")
                        if resource.get('external_url'):
                            st.markdown(f"[🔗 External Link]({resource['external_url']})")
                    with col2:
                        st.caption(f"Uploaded: {format_timestamp(resource.get('timestamp', ''))}")

def project_showcase_page():
    st.title("🚀 Project Showcase")
    
    tab1, tab2 = st.tabs(["🎯 Browse Projects", "📤 Share Project"])
    
    with tab1:
        st.subheader("Community Projects")
        projects = db_manager.get_projects()
        
        if projects:
            # Filter and sort options
            col1, col2 = st.columns(2)
            with col1:
                categories = list(set([p['category'] for p in projects]))
                selected_category = st.selectbox("Filter by Category", ["All"] + categories, key="project_filter")
            with col2:
                sort_by = st.selectbox("Sort by", ["Newest", "Most Liked", "Most Viewed"], key="project_sort")
            
            # Apply filters
            filtered_projects = projects
            if selected_category != "All":
                filtered_projects = [p for p in projects if p['category'] == selected_category]
            
            # Display projects
            for project in filtered_projects:
                with st.expander(f"🚀 {project['title']} - {project['category']}"):
                    col1, col2 = st.columns([2, 1])
                    with col1:
                        st.write(f"**Author:** {project['author']}")
                        st.write(f"**Description:** {project.get('description', 'No description')}")
                        st.write(f"**Technologies:** {project.get('technologies', 'Not specified')}")
                        st.write(f"**Likes:** {project.get('likes', 0)} | **Views:** {project.get('views', 0)}")
                        
                        # Links
                        links_col1, links_col2 = st.columns(2)
                        with links_col1:
                            if project.get('github_url'):
                                st.markdown(f"[📂 GitHub Repository]({project['github_url']})")
                        with links_col2:
                            if project.get('demo_url'):
                                st.markdown(f"[🌐 Live Demo]({project['demo_url']})")
                    
                    with col2:
                        st.caption(f"Shared: {format_timestamp(project.get('timestamp', ''))}")
                        if project.get('image_url'):
                            try:
                                st.image(project['image_url'], width=200)
                            except:
                                st.write("📷 Image preview unavailable")
        else:
            st.info("No projects showcased yet. Share your work!")
    
    with tab2:
        st.subheader("Share Your Project")
        
        with st.form("project_form"):
            col1, col2 = st.columns(2)
            with col1:
                title = st.text_input("Project Title*", placeholder="e.g., Weather Dashboard App")
                author = st.text_input("Your Name*", placeholder="e.g., Jane Smith")
                category = st.selectbox("Category*", [
                    "Web Application", "Mobile App", "Data Science", "Machine Learning",
                    "Game", "Desktop Application", "API", "Library/Framework",
                    "DevOps Tool", "UI/UX Design", "Other"
                ])
                technologies = st.text_input("Technologies Used*", placeholder="e.g., React, Node.js, MongoDB")
            
            with col2:
                description = st.text_area("Project Description", placeholder="Describe what your project does...")
                github_url = st.text_input("GitHub Repository URL", placeholder="https://github.com/username/repo")
                demo_url = st.text_input("Live Demo URL", placeholder="https://yourproject.com")
            
            # Project image upload
            project_image = st.file_uploader(
    "Project Screenshot/Image (optional)",
    type=["jpg", "jpeg", "png", "gif"],
    help="Upload a screenshot or image of your project"
)
            
            submitted = st.form_submit_button("🚀 Share Project", use_container_width=True)
            
            if submitted and title and author and category and technologies:
                project_data = {
                    "id": str(uuid.uuid4()),
                    "title": title,
                    "author": author,
                    "category": category,
                    "description": description,
                    "technologies": technologies,
                    "github_url": github_url or None,
                    "demo_url": demo_url or None,
                    "timestamp": datetime.now().isoformat(),
                    "likes": 0,
                    "views": 0
                }
                
                # Handle image upload if present
                if project_image:
                    with st.spinner("🔄 Uploading project image..."):
                        upload_result = upload_to_supabase(project_image)
                        if upload_result:
                            project_data["image_url"] = upload_result["url"]
                
                # Save to database
                project_id = db_manager.add_project(project_data)
                if project_id:
                    st.success("✅ Project shared successfully!")
                    st.balloons()
                else:
                    st.error("Failed to share project. Please try again.")
            elif submitted:
                st.error("Please fill in all required fields.")

def documentation_page():
    st.title("📖 Documentation Hub")
    st.markdown("Quick access to popular documentation and learning resources")
    st.markdown("---")
    
    # Popular documentation links
    doc_categories = {
        "🐍 Python": {
            "Official Python Docs": "https://docs.python.org/3/",
            "Django Documentation": "https://docs.djangoproject.com/",
            "Flask Documentation": "https://flask.palletsprojects.com/",
            "FastAPI Documentation": "https://fastapi.tiangolo.com/",
            "NumPy Documentation": "https://numpy.org/doc/",
            "Pandas Documentation": "https://pandas.pydata.org/docs/",
        },
        "🌐 Web Development": {
            "MDN Web Docs": "https://developer.mozilla.org/",
            "React Documentation": "https://react.dev/",
            "Vue.js Documentation": "https://vuejs.org/guide/",
            "Angular Documentation": "https://angular.io/docs",
            "Node.js Documentation": "https://nodejs.org/docs/",
            "Express.js Documentation": "https://expressjs.com/",
        },
        "☁️ Cloud & DevOps": {
            "AWS Documentation": "https://docs.aws.amazon.com/",
            "Google Cloud Docs": "https://cloud.google.com/docs",
            "Azure Documentation": "https://docs.microsoft.com/azure/",
            "Docker Documentation": "https://docs.docker.com/",
            "Kubernetes Documentation": "https://kubernetes.io/docs/",
            "Terraform Documentation": "https://www.terraform.io/docs/",
        },
        "📊 Data Science": {
            "Scikit-learn Documentation": "https://scikit-learn.org/stable/",
            "TensorFlow Documentation": "https://www.tensorflow.org/guide",
            "PyTorch Documentation": "https://pytorch.org/docs/",
            "Matplotlib Documentation": "https://matplotlib.org/stable/",
            "Seaborn Documentation": "https://seaborn.pydata.org/",
            "Jupyter Documentation": "https://jupyter.org/documentation",
        },
        "🗄️ Databases": {
            "PostgreSQL Documentation": "https://www.postgresql.org/docs/",
            "MySQL Documentation": "https://dev.mysql.com/doc/",
            "MongoDB Documentation": "https://docs.mongodb.com/",
            "Redis Documentation": "https://redis.io/documentation",
            "SQLite Documentation": "https://sqlite.org/docs.html",
        },
    }
    
    # Display documentation categories
    for category, docs in doc_categories.items():
        st.subheader(category)
        cols = st.columns(2)
        for i, (doc_name, doc_url) in enumerate(docs.items()):
            with cols[i % 2]:
                st.markdown(f"• [📚 {doc_name}]({doc_url})")
        st.markdown("---")
    
    # Additional resources section
    st.subheader("🎓 Learning Platforms")
    learning_platforms = {
        "FreeCodeCamp": "https://www.freecodecamp.org/",
        "Codecademy": "https://www.codecademy.com/",
        "Khan Academy": "https://www.khanacademy.org/",
        "Coursera": "https://www.coursera.org/",
        "edX": "https://www.edx.org/",
        "Udemy": "https://www.udemy.com/",
    }
    
    cols = st.columns(3)
    for i, (platform, url) in enumerate(learning_platforms.items()):
        with cols[i % 3]:
            st.markdown(f"• [🎯 {platform}]({url})")

def admin_page():
    st.title("🔧 Admin Dashboard")
    
    if not check_admin_password():
        return
    
    st.markdown("---")
    
    # Admin statistics
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
    
    # Admin tabs
    tab1, tab2, tab3 = st.tabs(["📊 Manage Resources", "🚀 Manage Projects", "⚙️ System Settings"])
    
    with tab1:
        st.subheader("Resource Management")
        resources = db_manager.get_resources()
        
        if resources:
            for resource in resources:
                with st.expander(f"📚 {resource['title']} by {resource['author']}"):
                    col1, col2 = st.columns([3, 1])
                    with col1:
                        st.write(f"**Category:** {resource['category']}")
                        st.write(f"**Description:** {resource.get('description', 'N/A')}")
                        st.write(f"**Downloads:** {resource.get('downloads', 0)}")
                        st.write(f"**Likes:** {resource.get('likes', 0)}")
                        st.write(f"**Uploaded:** {format_timestamp(resource.get('timestamp', ''))}")
                        
                        if resource.get('file_url'):
                            st.markdown(f"[📁 File URL]({resource['file_url']})")
                        if resource.get('external_url'):
                            st.markdown(f"[🔗 External URL]({resource['external_url']})")
                    
                    with col2:
                        if st.button(f"🗑️ Delete", key=f"del_res_{resource['id']}"):
                            if db_manager.delete_resource(resource['id']):
                                st.success("Resource deleted!")
                                st.rerun()
                            else:
                                st.error("Failed to delete resource")
        else:
            st.info("No resources to manage")
    
    with tab2:
        st.subheader("Project Management")
        projects = db_manager.get_projects()
        
        if projects:
            for project in projects:
                with st.expander(f"🚀 {project['title']} by {project['author']}"):
                    col1, col2 = st.columns([3, 1])
                    with col1:
                        st.write(f"**Category:** {project['category']}")
                        st.write(f"**Description:** {project.get('description', 'N/A')}")
                        st.write(f"**Technologies:** {project.get('technologies', 'N/A')}")
                        st.write(f"**Likes:** {project.get('likes', 0)}")
                        st.write(f"**Views:** {project.get('views', 0)}")
                        st.write(f"**Shared:** {format_timestamp(project.get('timestamp', ''))}")
                        
                        if project.get('github_url'):
                            st.markdown(f"[📂 GitHub]({project['github_url']})")
                        if project.get('demo_url'):
                            st.markdown(f"[🌐 Demo]({project['demo_url']})")
                        if project.get('image_url'):
                            st.markdown(f"[🖼️ Image]({project['image_url']})")
                    
                    with col2:
                        if st.button(f"🗑️ Delete", key=f"del_proj_{project['id']}"):
                            if db_manager.delete_project(project['id']):
                                st.success("Project deleted!")
                                st.rerun()
                            else:
                                st.error("Failed to delete project")
        else:
            st.info("No projects to manage")
    
    with tab3:
        st.subheader("System Settings")
        
        # Database connection test
        st.write("**Database Connection:**")
        try:
            test_stats = db_manager.get_stats()
            st.success("✅ Database connection successful")
        except Exception as e:
            st.error(f"❌ Database connection failed: {str(e)}")
        
        # Storage test
        st.write("**Storage Connection:**")
        try:
            # Try to list buckets (this will test the connection)
            result = supabase_admin.storage.list_buckets()
            st.success("✅ Storage connection successful")
        except Exception as e:
            st.error(f"❌ Storage connection failed: {str(e)}")
        
        # Admin settings
        st.markdown("---")
        st.write("**Admin Actions:**")
        
        if st.button("🔄 Clear Cache"):
            st.cache_data.clear()
            st.success("Cache cleared!")
        
        if st.button("🚪 Logout Admin"):
            st.session_state.admin_authenticated = False
            st.success("Admin logged out!")
            st.rerun()

# --- Main Application Logic ---
def main():
    # Initialize session state
    init_session_state()
    
    # Check authentication
    if not require_auth():
        login_page()
        return
    
    # Sidebar navigation
    with st.sidebar:
        st.title("📚 V-Learn")
        st.markdown("---")
        
        # User info
        current_user = get_current_user()
        if current_user:
            st.write(f"👋 Welcome, **{current_user['full_name']}**!")
            st.markdown("---")
        
        # Navigation menu
        page_options = {
            "🏠 Home": "home",
            "📁 Resource Library": "resources", 
            "🚀 Project Showcase": "projects",
            "📖 Documentation": "documentation",
            "🔧 Admin": "admin"
        }
        
        for label, page_key in page_options.items():
            if st.button(label, use_container_width=True):
                st.session_state.current_page = page_key
        
        st.markdown("---")
        
        # Logout button
        if st.button("🚪 Logout", use_container_width=True):
            logout()
    
    # Main content area
    current_page = st.session_state.get('current_page', 'home')
    
    if current_page == 'home':
        main_page()
    elif current_page == 'resources':
        resource_library_page()
    elif current_page == 'projects':
        project_showcase_page()
    elif current_page == 'documentation':
        documentation_page()
    elif current_page == 'admin':
        admin_page()
    else:
        main_page()

# --- App Entry Point ---
if __name__ == "__main__":
    main()
