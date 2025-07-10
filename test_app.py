import streamlit as st

def main():
    st.title("🔒 AutoPatchAI Test")
    st.write("If you can see this, Streamlit is working!")
    
    st.header("Testing Components")
    
    # Test basic Streamlit components
    st.write("✅ Basic text display")
    st.info("✅ Info message")
    st.success("✅ Success message")
    st.warning("✅ Warning message")
    st.error("✅ Error message")
    
    # Test sidebar
    with st.sidebar:
        st.header("📋 Sidebar Test")
        test_option = st.radio("Test Options", ["Option 1", "Option 2", "Option 3"])
        st.write(f"Selected: {test_option}")
    
    # Test columns
    col1, col2 = st.columns(2)
    with col1:
        st.write("✅ Column 1")
    with col2:
        st.write("✅ Column 2")
    
    # Test button
    if st.button("🚀 Test Button"):
        st.success("✅ Button clicked!")
    
    # Test file upload
    uploaded_file = st.file_uploader("Test File Upload", type=['txt'])
    if uploaded_file is not None:
        st.write("✅ File uploaded successfully!")

if __name__ == "__main__":
    main() 