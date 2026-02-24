#!/bin/bash

echo "🔧 Updating API URLs in frontend files..."

cd frontend

# Ajouter config.js dans chaque HTML s'il n'existe pas
for file in *.html; do
  if ! grep -q "config.js" "$file"; then
    echo "Adding config.js to $file"
    sed -i '/<\/head>/i <script src="./config.js"></script>' "$file"
  fi
done

echo "✅ All files updated to use API_CONFIG"
echo "📝 Next steps:"
echo "   1. Edit config.js with your Render URL"
echo "   2. Test locally"
echo "   3. Deploy!"

