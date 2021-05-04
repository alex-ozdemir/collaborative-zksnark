library(tidyverse)
d <- read_csv("./analysis/data/exp.csv")
data <- d 
ggplot(data=data, mapping = aes(y = time, x = constraints, color = infra, linetype=infra, shape=infra)) +
  geom_line() +
  geom_point(size=4) +
  scale_y_continuous(trans = "log2") +
  scale_x_continuous(trans = "log2") +
  facet_wrap(vars(proof))
ggsave("./analysis/plots/exp.png", width=8, height=6)
