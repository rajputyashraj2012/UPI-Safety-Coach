import streamlit as st
from google import genai
from google.genai import types

# Page configuration
st.set_page_config(page_title="UPI Safety AI", page_icon="🛡️")

st.title("🛡️ UPI Safety Coach")
st.caption("Your AI-powered UPI fraud awareness assistant")

# Connect Gemini
client = genai.Client(api_key=st.secrets["GEMINI_API_KEY"])

# System instructions
system_instruction = """
You are UPI Safety Coach, an expert digital payment safety assistant.

Your responsibilities:
1. Explain UPI safety and digital payment security.
2. Identify common UPI scams and fraud techniques.
3. Explain how to report UPI fraud in India.
4. Give practical fraud prevention advice.
5. Support Hindi and English.
6. Give simple, detailed and accurate answers.
7. Never ask users to share their UPI PIN, OTP,
   password, CVV or bank details.
8. If someone reports an active financial fraud,
   advise them to contact their bank immediately
   and call India's cybercrime helpline 1930.
"""

# Store chat history
if "messages" not in st.session_state:
    st.session_state.messages = []

# Display previous messages
for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])

# Chat input
if prompt := st.chat_input("Ask anything about UPI safety..."):

    st.session_state.messages.append(
        {"role": "user", "content": prompt}
    )

    with st.chat_message("user"):
        st.markdown(prompt)

    # Prepare conversation history
    contents = [
        types.Content(
            role="user" if msg["role"] == "user" else "model",
            parts=[types.Part(text=msg["content"])]
        )
        for msg in st.session_state.messages
    ]

    with st.chat_message("assistant"):
        try:
            response = client.models.generate_content(
                model="gemini-3.8-flash",
                contents=contents,
                config=types.GenerateContentConfig(
                    system_instruction=system_instruction,
                    temperature=0.5,
                    max_output_tokens=1200
                )
            )

            answer = response.text or "Please try asking again."
            st.markdown(answer)

            st.session_state.messages.append(
                {"role": "assistant", "content": answer}
            )

        except Exception as e:
            st.error(f"AI Error: {e}")