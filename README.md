# 📚 V-Learn: Learning Resources on the Go

**Your community-driven learning platform built with Streamlit and Supabase**

## 🎯 Overview

V-Learn is a comprehensive learning platform that enables communities to share, discover, and showcase educational resources and projects. Whether you're a student, educator, or developer, V-Learn provides the tools you need to build a collaborative learning environment.

## ✨ Features

### 📖 Documentation Hub
- Quick access to popular development documentation
- Organized by categories (Python, Web Dev, Cloud, AI/ML, etc.)
- Searchable documentation library
- Direct links to official resources

### 📁 Resource Library
- **File Upload**: Share PDFs, images, videos, documents
- **External Links**: Share web resources, tutorials, articles
- **Hybrid Sharing**: Combine files with external links
- **Smart Search**: Find resources by title, author, category, or description
- **Category Filtering**: Organize by Programming, Data Science, Design, etc.
- **Download Tracking**: Monitor resource popularity

### 🚀 Project Showcase
- Share your coding projects with the community
- Include GitHub repositories and live demo links
- Upload project screenshots and images
- Categorize by project type (Web App, Mobile, AI/ML, etc.)
- Track likes and views

### 🔧 Admin Panel
- Complete platform management
- Resource and project moderation
- Platform analytics and statistics
- Database health monitoring
- User activity tracking

## 🛠️ Technology Stack

- **Frontend**: Streamlit
- **Backend**: Python
- **Database**: Supabase (PostgreSQL)
- **Storage**: Supabase Storage
- **Authentication**: Simple admin password system
- **Deployment**: Streamlit Cloud ready

## 📋 Prerequisites

- Python 3.8 or higher
- Supabase account and project
- Git (for cloning)

## 🚀 Quick Start

### 1. Clone the Repository

```bash
git clone https://code.swecha.org/soai2025/techleads/soai-techlead-hackathon/v-learn
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Set Up Supabase

1. Create a new project at [Supabase](https://supabase.com/)
2. Go to your project's SQL editor
3. Run the following SQL to create the required tables:

```sql
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

-- Create policies for public access
CREATE POLICY "Public read access for resources" ON resources FOR SELECT USING (true);
CREATE POLICY "Public read access for projects" ON projects FOR SELECT USING (true);
CREATE POLICY "Public insert access for resources" ON resources FOR INSERT WITH CHECK (true);
CREATE POLICY "Public insert access for projects" ON projects FOR INSERT WITH CHECK (true);
```

4. Create a storage bucket named `vlearn` in Supabase Storage
5. Set the bucket to public access

### 4. Configure Environment

Create a `.streamlit/secrets.toml` file in your project root:

```toml
[supabase]
url = "your_supabase_project_url"
anon_key = "your_supabase_anon_key"  
service_role_key = "your_supabase_service_role_key"

[admin]
password = "your_admin_password"
```

**For local development**, you can also use environment variables:
```bash
export SUPABASE_URL="your_supabase_project_url"
export SUPABASE_ANON_KEY="your_supabase_anon_key"
export SUPABASE_SERVICE_KEY="your_supabase_service_role_key"
```

### 5. Run the Application

```bash
streamlit run app.py
```

The application will be available at `http://localhost:8501`

## 🌐 Deployment

### Streamlit Cloud

1. Push your code to a public repository
2. Connect your repository to [Streamlit Cloud](https://streamlit.io/cloud)
3. Add your secrets in the Streamlit Cloud dashboard:
   - Go to App Settings → Secrets
   - Add your `secrets.toml` content

### Other Platforms

V-Learn can be deployed on any platform that supports Streamlit:
- Heroku
- Railway
- Digital Ocean
- AWS EC2
- Google Cloud Run

## 📁 Project Structure

```
v-learn/
├── app.py                 # Main application file
├── requirements.txt       # Python dependencies
├── README.md             # This file
├── .streamlit/
│   └── secrets.toml      # Configuration secrets
└── .gitignore           # Git ignore file
```

## 🎮 Usage Guide

### For Users

1. **Browse Resources**: Explore the resource library to find learning materials
2. **Search & Filter**: Use search and category filters to find specific content
3. **Upload Resources**: Share your own files or link to external resources
4. **Showcase Projects**: Display your coding projects with demos and source code
5. **Access Documentation**: Quick access to popular development documentation

### For Admins

1. **Access Admin Panel**: Use the admin password to access management features
2. **Monitor Platform**: View statistics and platform health
3. **Moderate Content**: Review and manage uploaded resources and projects
4. **Manage Users**: Track user activity and engagement

## 🔧 Configuration Options

### Categories

You can customize categories in the code:

**Resource Categories:**
- Programming
- Web Development  
- Data Science
- Design
- Machine Learning
- Mobile Development
- DevOps
- Database
- UI/UX
- Cybersecurity
- Cloud Computing
- Other

**Project Categories:**
- Web Application
- Mobile App
- Data Science
- Machine Learning
- Game
- Desktop Application
- API
- Library/Framework
- DevOps Tool
- UI/UX Design
- Other

## 🛡️ Security Features

- Row Level Security (RLS) enabled on all tables
- Admin authentication for management functions
- Secure file upload with validation
- URL validation for external links
- XSS protection through Streamlit

## 🐛 Troubleshooting

### Common Issues

**Database Connection Error:**
- Verify your Supabase credentials
- Check if tables are created properly
- Ensure RLS policies are in place

**File Upload Issues:**
- Check Supabase storage bucket configuration
- Verify bucket is set to public access
- Ensure service role key has storage permissions

**Admin Access Problems:**
- Verify admin password in secrets
- Check if admin authentication is working

### Getting Help

If you encounter issues:
1. Check the Streamlit logs in your terminal
2. Verify your Supabase project configuration
3. Ensure all environment variables are set correctly
4. Check the database tables exist and have proper permissions

## 🤝 Contributing

We welcome contributions! Here's how you can help:

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/amazing-feature`
3. **Commit your changes**: `git commit -m 'Add amazing feature'`
4. **Push to the branch**: `git push origin feature/amazing-feature`
5. **Open a Pull Request**

### Development Guidelines

- Follow Python PEP 8 style guidelines
- Add comments for complex functionality
- Test your changes locally before submitting
- Update documentation for new features

## 📊 Platform Statistics

Track your platform's growth:
- Total resources shared
- Projects showcased
- Downloads and engagement
- User activity metrics

## 🔮 Future Enhancements

Planned features:
- User authentication and profiles
- Advanced search with AI
- Resource recommendations
- Mobile-responsive design improvements
- API endpoints for external integrations
- Advanced analytics dashboard
- Content moderation tools
- Social features (comments, ratings)

## 📄 License

This project is open source and available under the [MIT License](LICENSE).

## 👥 Authors

- **SOAI Tech Lead Hackathon Team** - *Initial work*

## 🙏 Acknowledgments

- [Streamlit](https://streamlit.io/) for the amazing web app framework
- [Supabase](https://supabase.com/) for the backend infrastructure
- The open source community for inspiration and resources

## 📞 Support

If you find V-Learn helpful, please consider:
- Giving it a ⭐ on the repository
- Sharing it with your community
- Contributing to the project
- Reporting bugs and suggesting features

---

**Happy Learning! 📚✨**
