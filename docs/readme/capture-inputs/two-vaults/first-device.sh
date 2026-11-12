# Device 1
printf '%s' demo-value |
  ai-vault set \
  DEMO_API_KEY --stdin \
  --group personal \
  --service demo
