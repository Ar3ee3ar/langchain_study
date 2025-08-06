import streamlit as st
# import langchain_tool.langchain_helper as lang_help
import langchain_tool.langchain_helper as lang_help

st.title("restaurant name generator")


cuisine = st.sidebar.selectbox("pick a Cuisine", ("Indian", "Italian", "Mexican", "American"))

# def generate_restaurant_name_and_items(cusine):
#     return {
#         'restaurant_name':'Curry Delight',
#         'menu_items':'samosa, paneeer tikka'
#     }

if cuisine:
    response = lang_help.generate_restaurant_name_and_items(cuisine)
    st.header(response['restaurant_name'].strip())
    menu_items = response['menu_items'].strip().split(",")
    st.write("**Menu Items**")
    
    
    for item in menu_items:
        st.write("-", item)

