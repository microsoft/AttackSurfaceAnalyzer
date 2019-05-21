SELECT * FROM 
(SELECT
  path,
  COUNT(1) AS 'num'
FROM
  windows_files
GROUP BY
  path) a
WHERE CONVERT(INT, CONVERT(VARCHAR(12), a.num)) > 2
ORDER BY a.num DESC