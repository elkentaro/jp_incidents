/* The image and its caption work without JavaScript. This only translates the page. */
(() => {
  'use strict';
  const english = {};
  document.querySelectorAll('[data-copy]').forEach(node => { english[node.dataset.copy] = node.textContent; });
  english.alt = document.querySelector('[data-copy-alt]').alt;
  const copy = {
    en: english,
    ja: {
      key:'凡例', keyUpstream:'上流', keyDownstream:'下流', keyStandalone:'単独', keyBoth:'両方の役割', keyRelated:'その他の関係', keyRelationship:'記録された関係',
      proximity:'単独の点には記録された接続がありません。点の位置が近くても、関係があることを意味しません。',
      incidents:'インシデント', sources:'情報源', eyebrow:'インシデントのつながり', title:'インシデント関連マップ', badge:'毎日更新',
      intro:'組織名と識別情報を省き、公表済みインシデントのつながりを可視化しています。',
      explanation:'点はインシデントを表します。実線は記録された関係を、点の色は上流・下流・単独のインシデントを区別します。位置は地理や深刻度を表しません。',
      total:'収録インシデント', linked:'関係が記録されたインシデント', links:'記録された関係', networks:'つながったネットワーク',
      updated:'最終更新', open:'高解像度の画像を開く ↗',
      alt:'匿名化したインシデントの関連図。オレンジの上流ノードから青い下流ノードにつながり、紫の単独インシデントも同じマップ内に接続線なしで表示されています。',
      readingTitle:'マップの見方', reading:'オレンジは上流、青は下流、紫は関係が記録されていない単独のインシデントを示します。青緑は上流と下流の両方の役割、濃い灰色はその他の関係を示します。線がないことは、無関係である証明ではありません。',
      snapshotTitle:'この画像について', snapshot:'公開インデックスから24時間ごとに静止画像を更新します。組織名、インシデントID、出典リンク、発生日は省略し、接続パターンを保持しています。記録された関係の概観であり、日本のサイバーインシデントを網羅するものではありません。',
      sourceUpdated:'元データ更新', browse:'インシデント一覧を見る', footer:'公開情報に基づく、記録された関係の匿名化マップ。', back:'インシデント一覧へ'
    },
    es: {
      key:'Leyenda', keyUpstream:'Origen', keyDownstream:'Afectado', keyStandalone:'Independiente', keyBoth:'Ambos roles', keyRelated:'Otras relaciones', keyRelationship:'Relación registrada',
      proximity:'Los nodos independientes no tienen conexiones registradas; la proximidad no implica una relación.',
      incidents:'Incidentes', sources:'Fuentes', eyebrow:'LAS CONEXIONES ENTRE INCIDENTES', title:'Mapa de relaciones', badge:'Instantánea diaria',
      intro:'Una vista de las conexiones entre incidentes públicos, sin nombres de organizaciones ni identificadores.',
      explanation:'Cada punto representa un incidente. Las líneas continuas muestran relaciones registradas; los colores distinguen incidentes de origen, afectados e independientes. La posición no representa geografía ni gravedad.',
      total:'Incidentes en la imagen', linked:'Con conexiones registradas', links:'Conexiones registradas', networks:'Redes conectadas', updated:'Última actualización', open:'Abrir imagen en alta resolución ↗',
      alt:'Mapa anonimizado. Los nodos naranjas de origen conectan con nodos azules afectados; los incidentes independientes morados aparecen en el mismo mapa, sin líneas de conexión.',
      readingTitle:'Cómo leer el mapa', reading:'Naranja: origen; azul: afectado; morado: independiente, sin conexiones registradas. Verde azulado: ambos roles; gris oscuro: otras relaciones. La ausencia de una línea no demuestra que dos incidentes no estén relacionados.',
      snapshotTitle:'Acerca de esta imagen', snapshot:'La imagen estática se actualiza cada 24 horas a partir del índice público. Se omiten nombres, identificadores, enlaces y fechas de incidentes, conservando las conexiones. Muestra relaciones registradas, no todos los incidentes de Japón.',
      sourceUpdated:'Datos de origen actualizados', browse:'Ver el índice de incidentes', footer:'Informes públicos. Relaciones registradas. Una vista anonimizada.', back:'Volver a los incidentes'
    }
  };
  function apply(language) {
    if (!copy[language]) language = 'en';
    document.documentElement.lang = language;
    document.title = copy[language].title + ' — JP Incident Monitor';
    document.querySelectorAll('[data-copy]').forEach(node => { node.textContent = copy[language][node.dataset.copy]; });
    document.querySelector('[data-copy-alt]').alt = copy[language].alt;
    const dates = new Intl.DateTimeFormat(language === 'ja' ? 'ja-JP' : language === 'es' ? 'es' : 'en-GB', {
      timeZone:'UTC', dateStyle:'medium', timeStyle:'short'
    });
    document.querySelectorAll('time[datetime]').forEach(node => {
      node.textContent = dates.format(new Date(node.dateTime)) + ' UTC';
    });
    document.querySelectorAll('[data-lang]').forEach(button => {
      const active = button.dataset.lang === language;
      button.classList.toggle('is-active', active); button.setAttribute('aria-pressed', String(active));
    });
    try { localStorage.setItem('jp-incidents-language', language); } catch (_) {}
  }
  document.querySelectorAll('[data-lang]').forEach(button => button.addEventListener('click', () => apply(button.dataset.lang)));
  let language = 'en';
  try { language = localStorage.getItem('jp-incidents-language') || 'en'; } catch (_) {}
  apply(language);
})();
