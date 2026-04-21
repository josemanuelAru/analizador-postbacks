import streamlit as st
import pandas as pd
import re
from collections import Counter
from urllib.parse import urlparse, parse_qs

# Configuración de la página
st.set_page_config(page_title="Analizador de URLs y Tokens", layout="wide")

st.title("📊 Analizador de URLs (Versión Simplificada)")
st.markdown("Sube tu CSV para ver los **Tokens** y **Parámetros Únicos** (sin repeticiones).")

uploaded_file = st.file_uploader("Sube tu archivo CSV", type=["csv"])

if uploaded_file is not None:
    try:
        df = pd.read_csv(uploaded_file)
        
        # --- SECCIÓN 1: TOKENS EN POSTBACK URL ---
        st.divider()
        st.header("1. Tokens Únicos (Postback URL)")
        
        col_postback = next((c for c in df.columns if c.strip().lower() == "postback url"), None)
        
        if col_postback:
            token_pattern = re.compile(r'(\{.*?\}|\[.*?\]|<.*?>)')
            all_tokens = []
            urls_pb = df[col_postback].dropna().astype(str)
            for url in urls_pb:
                all_tokens.extend(token_pattern.findall(url))
            
            if all_tokens:
                # Contamos para el gráfico, pero mostramos tabla limpia
                token_counts = Counter(all_tokens)
                df_tokens = pd.DataFrame(token_counts.items(), columns=["Token", "Frecuencia"]).sort_values(by="Frecuencia", ascending=False)
                
                c1, c2 = st.columns([1, 2])
                with c1:
                    st.write("Lista de Tokens detectados:")
                    # Mostramos solo el nombre del token una vez
                    st.dataframe(df_tokens[["Token"]].reset_index(drop=True), use_container_width=True)
                with c2:
                    st.write("Frecuencia de uso:")
                    st.bar_chart(df_tokens.set_index("Token"))
            else:
                st.info("No se encontraron tokens.")
        else:
            st.warning("Columna 'Postback Url' no encontrada.")

        # --- SECCIÓN 2: PARÁMETROS ÚNICOS (ORIGINAL URL) ---
        st.divider()
        st.header("2. Parámetros Únicos Detectados (Original URL)")
        
        col_original = next((c for c in df.columns if c.strip().lower() == "original url"), None)
        
        if col_original:
            all_params_pairs = [] # Para (Nombre, Valor)
            param_names = set()   # Usamos un set para nombres únicos automáticamente
            
            urls_orig = df[col_original].dropna().astype(str)
            
            for url in urls_orig:
                parsed_url = urlparse(url)
                params = parse_qs(parsed_url.query)
                
                for key, values in params.items():
                    param_names.add(key) # Guardar nombre único
                    for val in values:
                        all_params_pairs.append({"Parámetro": key, "Valor": val})
            
            if param_names:
                # A. Tabla de nombres de parámetros que NO se repiten
                st.subheader("📋 Nombres de parámetros encontrados (Sin duplicados)")
                df_unique_names = pd.DataFrame(sorted(list(param_names)), columns=["Nombre del Parámetro"])
                st.dataframe(df_unique_names, use_container_width=True)
                
                # B. Tabla de combinaciones Nombre-Valor Únicas
                st.subheader("🔗 Combinaciones de Valor únicas")
                st.caption("Si un parámetro tiene el mismo valor en varias filas, aquí solo se muestra una vez.")
                df_unique_pairs = pd.DataFrame(all_params_pairs).drop_duplicates().sort_values(by="Parámetro")
                st.dataframe(df_unique_pairs.reset_index(drop=True), use_container_width=True)

                # --- SECCIÓN 3: VALORES ÚNICOS APPSFLYER ---
                st.divider()
                st.header("3. Filtro Específico AppsFlyer")
                
                col_af1, col_af2 = st.columns(2)
                
                with col_af1:
                    st.subheader("af_xplatform_vt_lookback")
                    lookback_vals = df_unique_pairs[df_unique_pairs["Parámetro"] == "af_xplatform_vt_lookback"]["Valor"].unique()
                    if len(lookback_vals) > 0:
                        st.table(pd.DataFrame(lookback_vals, columns=["Valores Únicos"]))
                    else:
                        st.info("No detectado.")
                        
                with col_af2:
                    st.subheader("af_pmod_priority")
                    priority_vals = df_unique_pairs[df_unique_pairs["Parámetro"] == "af_pmod_priority"]["Valor"].unique()
                    if len(priority_vals) > 0:
                        st.table(pd.DataFrame(priority_vals, columns=["Valores Únicos"]))
                    else:
                        st.info("No detectado.")
            else:
                st.info("No se detectaron parámetros en la Original URL.")
        else:
            st.warning("Columna 'Original URL' no encontrada.")
                
    except Exception as e:
        st.error(f"Error: {e}")
