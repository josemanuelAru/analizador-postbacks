import streamlit as st
import pandas as pd
import re
from collections import Counter

# Configuración básica de la página
st.set_page_config(page_title="Analizador de Tokens Postback", layout="centered")

st.title("🔗 Analizador de Tokens en Postback URLs")
st.markdown("Sube tu CSV para contar cuántas veces se utiliza cada macro/token en tus enlaces de afiliado.")

# 1. Widget para subir el archivo
uploaded_file = st.file_uploader("Sube tu archivo CSV", type=["csv"])

if uploaded_file is not None:
    try:
        # Leer el CSV
        df = pd.read_csv(uploaded_file)
        
        # 2. Buscar la columna "Postback Url" (ignorando mayúsculas/minúsculas o espacios extra)
        col_name = None
        for col in df.columns:
            if col.strip().lower() == "postback url":
                col_name = col
                break
        
        if not col_name:
            st.error("❌ No se encontró la columna 'Postback Url' en el CSV. Por favor revisa los encabezados de tu archivo.")
        else:
            st.success(f"✅ CSV cargado. Procesando la columna: '{col_name}'")
            
            # 3. Lógica para extraer los tokens
            # Esta expresión regular busca cualquier texto entre {}, [] o <>
            token_pattern = re.compile(r'(\{.*?\}|\[.*?\]|<.*?>)')
            
            all_tokens = []
            
            # Limpiamos valores nulos (celdas vacías) y convertimos todo a texto
            urls = df[col_name].dropna().astype(str)
            
            # Extraemos los tokens de cada URL y los metemos en una lista gigante
            for url in urls:
                tokens = token_pattern.findall(url)
                all_tokens.extend(tokens)
            
            if all_tokens:
                # 4. Contar los tokens
                token_counts = Counter(all_tokens)
                
                # Convertir a DataFrame para que se vea bonito en Streamlit
                df_results = pd.DataFrame(token_counts.items(), columns=["Token", "Frecuencia"])
                df_results = df_results.sort_values(by="Frecuencia", ascending=False).reset_index(drop=True)
                
                # 5. Mostrar Resultados
                st.write("### 📊 Desglose de Tokens Utilizados")
                st.dataframe(df_results, use_container_width=True)
                
                st.write("### 📈 Gráfico de Frecuencias")
                # Preparamos los datos para el gráfico de barras nativo de Streamlit
                st.bar_chart(df_results.set_index("Token"))
                
            else:
                st.warning("⚠️ No se encontraron tokens (ej. {clickid}, [sub1]) en las URLs proporcionadas.")
                
    except Exception as e:
        st.error(f"Ocurrió un error al procesar el archivo: {e}")
