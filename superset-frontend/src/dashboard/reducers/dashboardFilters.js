/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
/* eslint-disable camelcase */
import {
  CHANGE_FILTER,
  UPDATE_DIRECT_PATH_TO_FILTER,
  UPDATE_LAYOUT_COMPONENTS,
  UPDATE_DASHBOARD_FILTERS_SCOPE,
} from '../actions/dashboardFilters';
import { HYDRATE_DASHBOARD } from '../actions/hydrate';
import { DASHBOARD_ROOT_ID } from '../util/constants';
import { buildActiveFilters } from '../util/activeDashboardFilters';
import { getChartIdAndColumnFromFilterKey } from '../util/getDashboardFilterKey';

export const DASHBOARD_FILTER_SCOPE_GLOBAL = {
  scope: [DASHBOARD_ROOT_ID],
  immune: [],
};

export const dashboardFilter = {
  chartId: null,
  componentId: null,
  filterName: null,
  datasourceId: null,
  directPathToFilter: [],
  isDateFilter: false,
  isInstantFilter: true,
  columns: {},
  labels: {},
  scopes: {},
};

const CHANGE_FILTER_VALUE_ACTIONS = [CHANGE_FILTER];

export default function dashboardFiltersReducer(dashboardFilters = {}, action) {
  const actionHandlers = {
    [CHANGE_FILTER](state) {
      const { newSelectedValues, merge } = action;
      const updatedColumns = Object.keys(newSelectedValues).reduce(
        (columns, name) => {
          // override existed column value, or add new column name
          if (!merge || !(name in columns)) {
            return {
              ...columns,
              [name]: newSelectedValues[name],
            };
          }

          return {
            ...columns,
            [name]: [...columns[name], ...newSelectedValues[name]],
          };
        },
        { ...state.columns },
      );

      return {
        ...state,
        columns: updatedColumns,
      };
    },

    [UPDATE_DIRECT_PATH_TO_FILTER](state) {
      const { path } = action;
      return {
        ...state,
        directPathToFilter: path,
      };
    },
  };

  if (action.type === UPDATE_LAYOUT_COMPONENTS) {
    buildActiveFilters({
      dashboardFilters,
      components: action.components,
    });
    return dashboardFilters;
  }
  if (action.type === UPDATE_DASHBOARD_FILTERS_SCOPE) {
    const allDashboardFiltersScope = action.scopes;
    // update filter scope for each filter field
    const updatedFilters = Object.entries(allDashboardFiltersScope).reduce(
      (map, entry) => {
        const [filterKey, { scope, immune }] = entry;
        const { chartId, column } = getChartIdAndColumnFromFilterKey(filterKey);
        const scopes = {
          ...map[chartId].scopes,
          [column]: {
            scope,
            immune,
          },
        };
        return {
          ...map,
          [chartId]: {
            ...map[chartId],
            scopes,
          },
        };
      },
      dashboardFilters,
    );

    buildActiveFilters({ dashboardFilters: updatedFilters });
    return updatedFilters;
  }
  if (action.type === HYDRATE_DASHBOARD) {
    return action.data.dashboardFilters;
  }

  if (action.type in actionHandlers) {
    const updatedFilters = {
      ...dashboardFilters,
      [action.chartId]: actionHandlers[action.type](
        dashboardFilters[action.chartId],
      ),
    };
    if (CHANGE_FILTER_VALUE_ACTIONS.includes(action.type)) {
      buildActiveFilters({ dashboardFilters: updatedFilters });
    }

    return updatedFilters;
  }

  return dashboardFilters;
}
