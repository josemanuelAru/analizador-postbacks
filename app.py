import streamlit as st
import pandas as pd
import re
from collections import Counter
from urllib.parse import urlparse, parse_qs

# Configuración de la página
st.set_page_config(page_title="Analizador de URLs y Tokens", layout="wide")

st.title("📊 Analizador Avanzado de URLs de Afiliación")
st.markdown("Sube tu CSV para desglosar **Tokens** y **Parámetros de URL**.")

uploaded_file = st.file_uploader("Sube tu archivo CSV", type=["csv"])

if uploaded_file is not None:
    try:
        df = pd.read_csv(uploaded_file)
        
        # --- SECCIÓN 1: TOKENS EN POSTBACK URL ---
        st.divider()
        st.header("1. Contador de Tokens (Postback URL)")
        
        col_postback = next((c for c in df.columns if c.strip().lower() == "postback url"), None)
        
        if col_postback:
            token_pattern = re.compile(r'(\{.*?\}|\[.*?\]|<.*?>)')
            all_tokens = []
            urls_pb = df[col_postback].dropna().astype(str)
            for url in urls_pb:
                all_tokens.extend(token_pattern.findall(url))
            
            if all_tokens:
                token_counts = Counter(all_tokens)
                df_tokens = pd.DataFrame(token_counts.items(), columns=["Token", "Frecuencia"]).sort_values(by="Frecuencia", ascending=False)
                
                c1, c2 = st.columns([1, 2])
                c1.dataframe(df_tokens, use_container_width=True)
                c2.bar_chart(df_tokens.set_index("Token"))
            else:
                st.info("No se encontraron tokens en la columna Postback URL.")
        else:
            st.warning("Columna 'Postback Url' no encontrada.")

        # --- SECCIÓN 2: DESGLOSE DE PARÁMETROS (ORIGINAL URL) ---
        st.divider()
        st.header("2. Desglose de Parámetros (Original URL)")
        
        col_original = next((c for c in df.columns if c.strip().lower() == "original url"), None)
        
        if col_original:
            all_params_data = [] # Para la tabla de Nombre | Valor
            param_names_counter = [] # Para el contador de nombres
            
            urls_orig = df[col_original].dropna().astype(str)
            
            for url in urls_orig:
                # Extraemos los parámetros de la URL
                parsed_url = urlparse(url)
                params = parse_qs(parsed_url.query)
                
                for key, values in params.items():
                    for val in values:
                        all_params_data.append({"Nombre del Parámetro": key, "Valor": val})
                        param_names_counter.append(key)
            
            if all_params_data:
                # Tabla 1: Todos los parámetros y sus valores
                st.subheader("📋 Lista de Parámetros y Valores detectados")
                df_params_all = pd.DataFrame(all_params_data)
                st.dataframe(df_params_all, use_container_width=True)
                
                # Tabla 2 y Contador: Frecuencia de cada parámetro
                st.subheader("🔢 Contador de uso por Nombre de Parámetro")
                name_counts = Counter(param_names_counter)
                df_name_counts = pd.DataFrame(name_counts.items(), columns=["Nombre del Parámetro", "Veces Utilizado"]).sort_values(by="Veces Utilizado", ascending=False)
                
                col_t1, col_t2 = st.columns([1, 1])
                col_t1.write("Frecuencia:")
                col_t1.dataframe(df_name_counts, use_container_width=True)
                col_t2.write("Visualización:")
                col_t2.bar_chart(df_name_counts.set_index("Nombre del Parámetro"))
            else:
                st.info("No se detectaron parámetros (ej. ?sub1=val&sub2=val) en la Original URL.")
        else:
            st.warning("Columna 'Original URL' no encontrada.")
                
    except Exception as e:
        st.error(f"Error procesando el archivo: {e}")
