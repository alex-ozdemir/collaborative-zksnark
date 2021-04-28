library(tidyverse)
d <- read_csv("./analysis/data/groth16.csv")
data <- d %>% transmute(constraints=constraints, mpc=mpc_time, local=local_time) %>% pivot_longer(!constraints, names_to = "infra", values_to = "time")
ggplot(data=data, mapping = aes(y = time, x = constraints, color = infra, linetype=infra, shape=infra)) +
  geom_line() +
  geom_point(size=4) +
  scale_y_continuous(trans = "log2") +
  scale_x_continuous(trans = "log2")
ggsave("./analysis/plots/groth16.png")
